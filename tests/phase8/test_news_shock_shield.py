"""Unit tests for Phase 8 Item 4: High-Impact Economic Calendar News Shock Shield."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from cas_forex_revamp.risk import (
    DEFAULT_POST_MINUTES,
    DEFAULT_PRE_MINUTES,
    ENTRY_ACTIONS,
    EconomicEvent,
    MAX_CALENDAR_PAYLOAD_BYTES,
    NewsCalendarParseError,
    NewsImpact,
    NewsShieldDecision,
    NewsShockShield,
    PROTECTIVE_ACTIONS,
    RED_FLAG_CATEGORIES,
    TradeActionType,
    currencies_for_symbol,
    load_calendar_file,
    load_calendar_json,
    normalize_symbol,
    validate_https_calendar_url,
)


def _utc(year: int, month: int, day: int, hour: int, minute: int, second: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def _event(
    event_id: str,
    title: str,
    currency: str,
    impact: NewsImpact,
    scheduled_utc: datetime,
    category: str = "CPI",
    source: str = "offline_calendar",
) -> EconomicEvent:
    return EconomicEvent(
        event_id=event_id,
        title=title,
        currency=currency,
        impact=impact,
        scheduled_utc=scheduled_utc,
        category=category,
        source=source,
    )


class TestCurrencyExposureMapping(unittest.TestCase):
    def test_indices_metals_and_fx_normalization(self) -> None:
        # US equity indices -> USD
        for sym in ("NAS100", "USTEC", "US100", "NAS100_USD", "US30", "DJ30", "WS30", "SPX500", "US500", "US500.cash"):
            self.assertEqual(currencies_for_symbol(sym), frozenset({"USD"}), msg=f"Failed for {sym}")

        # Precious metals -> USD
        for sym in ("XAUUSD", "XAU_USD", "XAU/USD", "GOLD", "XAGUSD", "SILVER"):
            self.assertEqual(currencies_for_symbol(sym), frozenset({"USD"}), msg=f"Failed for {sym}")

        # Regional equity indices
        for sym in ("GER40", "DAX40", "DE40"):
            self.assertEqual(currencies_for_symbol(sym), frozenset({"EUR"}), msg=f"Failed for {sym}")
        self.assertEqual(currencies_for_symbol("UK100"), frozenset({"GBP"}))
        self.assertEqual(currencies_for_symbol("JP225"), frozenset({"JPY"}))

        # FX pairs with separators, casing, broker suffixes, Kraken prefixes
        self.assertEqual(currencies_for_symbol("EUR_USD"), frozenset({"EUR", "USD"}))
        self.assertEqual(currencies_for_symbol("eurusd"), frozenset({"EUR", "USD"}))
        self.assertEqual(currencies_for_symbol("EUR/USD"), frozenset({"EUR", "USD"}))
        self.assertEqual(currencies_for_symbol("EURUSD.pro"), frozenset({"EUR", "USD"}))
        self.assertEqual(currencies_for_symbol("ZEURZUSD"), frozenset({"EUR", "USD"}))
        self.assertEqual(currencies_for_symbol("GBP_JPY"), frozenset({"GBP", "JPY"}))
        self.assertEqual(currencies_for_symbol("GBPJPY"), frozenset({"GBP", "JPY"}))
        self.assertEqual(currencies_for_symbol("USD_CAD"), frozenset({"USD", "CAD"}))
        self.assertEqual(currencies_for_symbol("USDCAD"), frozenset({"USD", "CAD"}))
        self.assertEqual(currencies_for_symbol("EUR_GBP"), frozenset({"EUR", "GBP"}))
        self.assertEqual(normalize_symbol("ustec"), "NAS100")
        self.assertEqual(normalize_symbol("eur_usd"), "EURUSD")

    def test_unknown_symbol_safe_fallback_and_strict_mode(self) -> None:
        self.assertEqual(currencies_for_symbol("MYSTERY_TOKEN_99", strict_unknown_symbol=False), frozenset())
        self.assertEqual(
            currencies_for_symbol("MYSTERY_TOKEN_99", strict_unknown_symbol=True),
            frozenset({"USD"}),
        )

        cpi_time = _utc(2026, 11, 20, 13, 30, 0)
        cpi = _event("ev-cpi", "US CPI YoY", "USD", NewsImpact.HIGH, cpi_time, category="CPI")

        permissive_shield = NewsShockShield([cpi], strict_unknown_symbol=False)
        d_perm = permissive_shield.evaluate("MYSTERY_TOKEN_99", TradeActionType.OPEN_NEW, now_utc=cpi_time)
        self.assertTrue(d_perm.allowed)
        self.assertEqual(d_perm.reason_code, "UNKNOWN_SYMBOL")

        strict_shield = NewsShockShield([cpi], strict_unknown_symbol=True)
        d_strict = strict_shield.evaluate("MYSTERY_TOKEN_99", TradeActionType.OPEN_NEW, now_utc=cpi_time)
        self.assertFalse(d_strict.allowed)
        self.assertEqual(d_strict.reason_code, "NEW_ENTRY_PAUSED_NEWS_WINDOW")
        self.assertEqual(d_strict.blocking_events, (cpi,))

        # Protective action on unknown symbol in strict mode is STILL allowed
        d_prot = strict_shield.evaluate("MYSTERY_TOKEN_99", TradeActionType.CLOSE_POSITION, now_utc=cpi_time)
        self.assertTrue(d_prot.allowed)
        self.assertEqual(d_prot.reason_code, "PROTECTIVE_ACTION_ALWAYS_ALLOWED")


class TestBlackoutWindowAndInvariants(unittest.TestCase):
    def setUp(self) -> None:
        self.cpi_time = _utc(2026, 11, 20, 13, 30, 0)
        self.nfp_time = _utc(2026, 12, 4, 13, 30, 0)
        self.fomc_time = _utc(2026, 12, 16, 19, 0, 0)
        self.cpi = _event("usd-cpi-01", "US CPI YoY", "USD", NewsImpact.HIGH, self.cpi_time, category="CPI")
        self.nfp = _event("usd-nfp-01", "US Non-Farm Payrolls", "USD", NewsImpact.HIGH, self.nfp_time, category="NFP")
        self.fomc = _event("usd-fomc-01", "FOMC Rate Decision", "USD", NewsImpact.HIGH, self.fomc_time, category="FOMC")
        self.shield = NewsShockShield([self.cpi, self.nfp, self.fomc])

    def test_default_window_blocks_usd_exposed_entries_and_allows_eur_gbp(self) -> None:
        self.assertEqual(self.shield.pre_minutes, DEFAULT_PRE_MINUTES)
        self.assertEqual(self.shield.post_minutes, DEFAULT_POST_MINUTES)
        self.assertEqual(self.shield.min_impact, NewsImpact.HIGH)

        for event_time, expected_event in (
            (self.cpi_time, self.cpi),
            (self.nfp_time, self.nfp),
            (self.fomc_time, self.fomc),
        ):
            for sym in ("NAS100", "US30", "XAUUSD", "EUR_USD"):
                for entry_action in (TradeActionType.OPEN_NEW, TradeActionType.ADD_POSITION):
                    dec = self.shield.evaluate(sym, entry_action, now_utc=event_time)
                    self.assertFalse(dec.allowed, msg=f"{sym} {entry_action} should be blocked at {event_time}")
                    self.assertEqual(dec.reason_code, "NEW_ENTRY_PAUSED_NEWS_WINDOW")
                    self.assertEqual(dec.blocking_events, (expected_event,))
                    self.assertEqual(dec.resume_at_utc, event_time + timedelta(minutes=5))
                    self.assertEqual(dec.evaluated_at_utc, event_time)

            # Unaffected cross pair EUR_GBP remains open for new entries
            for entry_action in (TradeActionType.OPEN_NEW, TradeActionType.ADD_POSITION):
                dec_eg = self.shield.evaluate("EUR_GBP", entry_action, now_utc=event_time)
                self.assertTrue(dec_eg.allowed)
                self.assertEqual(dec_eg.reason_code, "ALLOWED_NO_ACTIVE_NEWS")
                self.assertEqual(dec_eg.blocking_events, ())
                self.assertIsNone(dec_eg.resume_at_utc)

    def test_exact_boundary_timestamps(self) -> None:
        t_before_allowed = self.cpi_time - timedelta(minutes=5, seconds=1)
        t_start_blocked = self.cpi_time - timedelta(minutes=5)
        t_peak_blocked = self.cpi_time
        t_end_blocked = self.cpi_time + timedelta(minutes=5)
        t_after_allowed = self.cpi_time + timedelta(minutes=5, seconds=1)

        d1 = self.shield.evaluate("NAS100", TradeActionType.OPEN_NEW, now_utc=t_before_allowed)
        self.assertTrue(d1.allowed)
        self.assertEqual(d1.reason_code, "ALLOWED_NO_ACTIVE_NEWS")
        self.assertIsNone(d1.resume_at_utc)

        for blocked_ts in (t_start_blocked, t_peak_blocked, t_end_blocked):
            d_blk = self.shield.evaluate("NAS100", TradeActionType.OPEN_NEW, now_utc=blocked_ts)
            self.assertFalse(d_blk.allowed, msg=f"Expected blocked at {blocked_ts.isoformat()}")
            self.assertEqual(d_blk.reason_code, "NEW_ENTRY_PAUSED_NEWS_WINDOW")
            self.assertEqual(d_blk.resume_at_utc, t_end_blocked)

        d_after = self.shield.evaluate("NAS100", TradeActionType.OPEN_NEW, now_utc=t_after_allowed)
        self.assertTrue(d_after.allowed)
        self.assertEqual(d_after.reason_code, "ALLOWED_NO_ACTIVE_NEWS")
        self.assertIsNone(d_after.resume_at_utc)

    def test_critical_invariant_protective_actions_always_allowed_at_peak_news(self) -> None:
        protective_list = (
            TradeActionType.AMEND_STOP,
            TradeActionType.MOVE_BREAKEVEN,
            TradeActionType.TRAIL_STOP,
            TradeActionType.CLOSE_POSITION,
            TradeActionType.EMERGENCY_CLOSE_ALL,
        )
        self.assertEqual(frozenset(protective_list), PROTECTIVE_ACTIONS)
        self.assertEqual(frozenset({TradeActionType.OPEN_NEW, TradeActionType.ADD_POSITION}), ENTRY_ACTIONS)

        for peak_time in (self.cpi_time, self.nfp_time, self.fomc_time):
            for sym in ("NAS100", "US30", "XAUUSD", "EUR_USD"):
                for action in protective_list:
                    dec = self.shield.evaluate(sym, action, now_utc=peak_time)
                    self.assertTrue(dec.allowed, msg=f"CRITICAL INVARIANT FAILED: {action} blocked on {sym}")
                    self.assertEqual(dec.reason_code, "PROTECTIVE_ACTION_ALWAYS_ALLOWED")
                    self.assertEqual(dec.blocking_events, ())
                    self.assertIsNone(dec.resume_at_utc)
                    self.assertEqual(dec.action, action)

    def test_low_and_medium_impact_ignored_when_min_impact_high(self) -> None:
        ev_time = _utc(2026, 11, 20, 15, 0, 0)
        low_ev = _event("usd-low", "Baker Hughes Rig Count", "USD", NewsImpact.LOW, ev_time, category="OIL")
        med_ev = _event("usd-med", "US Existing Home Sales", "USD", NewsImpact.MEDIUM, ev_time, category="HOUSING")

        high_shield = NewsShockShield([low_ev, med_ev], min_impact=NewsImpact.HIGH)
        d_high = high_shield.evaluate("NAS100", TradeActionType.OPEN_NEW, now_utc=ev_time)
        self.assertTrue(d_high.allowed)
        self.assertEqual(d_high.reason_code, "ALLOWED_NO_ACTIVE_NEWS")

        med_shield = NewsShockShield([low_ev, med_ev], min_impact=NewsImpact.MEDIUM)
        d_med = med_shield.evaluate("NAS100", TradeActionType.OPEN_NEW, now_utc=ev_time)
        self.assertFalse(d_med.allowed)
        self.assertEqual(d_med.blocking_events, (med_ev,))

        # Impact enum ordering check
        self.assertLess(NewsImpact.LOW, NewsImpact.MEDIUM)
        self.assertLess(NewsImpact.MEDIUM, NewsImpact.HIGH)
        self.assertGreater(NewsImpact.HIGH, NewsImpact.LOW)

    def test_overlapping_events_compute_exact_latest_resume_at_utc(self) -> None:
        t_cpi = _utc(2026, 11, 20, 13, 30, 0)
        t_retail = _utc(2026, 11, 20, 13, 33, 0)
        cpi = _event("ev-1-cpi", "US CPI", "USD", NewsImpact.HIGH, t_cpi, category="CPI")
        retail = _event("ev-2-retail", "US Retail Sales", "USD", NewsImpact.HIGH, t_retail, category="RETAIL_SALES")

        shield = NewsShockShield([retail, cpi], pre_minutes=5, post_minutes=5)

        # At 13:30:00Z, both CPI (13:25..13:35) and Retail Sales (13:28..13:38) are active
        d_both = shield.evaluate("US30", TradeActionType.OPEN_NEW, now_utc=_utc(2026, 11, 20, 13, 30, 0))
        self.assertFalse(d_both.allowed)
        self.assertEqual(d_both.blocking_events, (cpi, retail))
        self.assertEqual(d_both.resume_at_utc, _utc(2026, 11, 20, 13, 38, 0))

        # At 13:36:00Z, CPI window ended, Retail Sales still active until 13:38:00Z
        d_tail = shield.evaluate("US30", TradeActionType.ADD_POSITION, now_utc=_utc(2026, 11, 20, 13, 36, 0))
        self.assertFalse(d_tail.allowed)
        self.assertEqual(d_tail.blocking_events, (retail,))
        self.assertEqual(d_tail.resume_at_utc, _utc(2026, 11, 20, 13, 38, 0))

        # At 13:38:01Z, both windows have cleared
        d_clear = shield.evaluate("US30", TradeActionType.OPEN_NEW, now_utc=_utc(2026, 11, 20, 13, 38, 1))
        self.assertTrue(d_clear.allowed)
        self.assertIsNone(d_clear.resume_at_utc)

    def test_red_flag_categories_and_non_usd_central_banks(self) -> None:
        expected_flags = {
            "CPI",
            "NFP",
            "FOMC",
            "ECB",
            "BOE",
            "BOJ",
            "GDP",
            "PPI",
            "PCE",
            "RETAIL_SALES",
            "RATE_DECISION",
        }
        self.assertTrue(expected_flags.issubset(RED_FLAG_CATEGORIES))

        ecb_time = _utc(2026, 11, 21, 13, 15, 0)
        boe_time = _utc(2026, 11, 22, 12, 0, 0)
        boj_time = _utc(2026, 11, 23, 3, 0, 0)
        events = [
            _event("ecb-1", "ECB Rate Decision", "EUR", NewsImpact.HIGH, ecb_time, category="ECB"),
            _event("boe-1", "BOE Bank Rate", "GBP", NewsImpact.HIGH, boe_time, category="BOE"),
            _event("boj-1", "BOJ Policy Rate", "JPY", NewsImpact.HIGH, boj_time, category="BOJ"),
        ]
        shield = NewsShockShield(events)

        self.assertFalse(shield.evaluate("GER40", TradeActionType.OPEN_NEW, now_utc=ecb_time).allowed)
        self.assertFalse(shield.evaluate("EUR_GBP", TradeActionType.OPEN_NEW, now_utc=ecb_time).allowed)
        self.assertTrue(shield.evaluate("NAS100", TradeActionType.OPEN_NEW, now_utc=ecb_time).allowed)

        self.assertFalse(shield.evaluate("UK100", TradeActionType.OPEN_NEW, now_utc=boe_time).allowed)
        self.assertFalse(shield.evaluate("GBP_JPY", TradeActionType.OPEN_NEW, now_utc=boe_time).allowed)

        self.assertFalse(shield.evaluate("JP225", TradeActionType.OPEN_NEW, now_utc=boj_time).allowed)
        self.assertFalse(shield.evaluate("GBP_JPY", TradeActionType.OPEN_NEW, now_utc=boj_time).allowed)


class TestOfflineCalendarParserAndStaleness(unittest.TestCase):
    def test_load_calendar_json_object_and_offset_normalization(self) -> None:
        payload = json.dumps(
            {
                "generated_at_utc": "2026-11-20T08:00:00Z",
                "source": "bls_offline_feed",
                "events": [
                    {
                        "event_id": "cpi-2026-11",
                        "title": "US CPI YoY",
                        "currency": "usd",
                        "impact": "high",
                        "scheduled_utc": "2026-11-20T08:30:00-05:00",
                        "category": "CPI",
                    }
                ],
            }
        )
        cal = load_calendar_json(payload)
        self.assertEqual(len(cal), 1)
        self.assertEqual(cal.generated_at_utc, _utc(2026, 11, 20, 8, 0, 0))
        ev = cal.events[0]
        self.assertEqual(ev.currency, "USD")
        self.assertEqual(ev.impact, NewsImpact.HIGH)
        self.assertEqual(ev.scheduled_utc, _utc(2026, 11, 20, 13, 30, 0))
        self.assertEqual(ev.source, "bls_offline_feed")
        self.assertEqual(len(cal.payload_sha256), 64)

        shield = NewsShockShield.from_json(payload)
        d = shield.evaluate("NAS100", TradeActionType.OPEN_NEW, now_utc=_utc(2026, 11, 20, 13, 30, 0))
        self.assertFalse(d.allowed)

    def test_load_calendar_file_and_rejects_oversized_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            good_path = Path(tmpdir) / "calendar.json"
            good_payload = json.dumps(
                [
                    {
                        "event_id": "fomc-1",
                        "title": "FOMC Statement",
                        "currency": "USD",
                        "impact": "HIGH",
                        "scheduled_utc": "2026-12-16T19:00:00Z",
                        "category": "FOMC",
                        "source": "fed",
                    }
                ]
            )
            good_path.write_text(good_payload, encoding="utf-8")
            cal = load_calendar_file(good_path)
            self.assertEqual(len(cal), 1)
            self.assertEqual(cal.events[0].event_id, "fomc-1")

            big_path = Path(tmpdir) / "oversized.json"
            big_path.write_bytes(b" " * (MAX_CALENDAR_PAYLOAD_BYTES + 1))
            with self.assertRaises(NewsCalendarParseError):
                load_calendar_file(big_path)

    def test_parser_rejects_malformed_naive_invalid_and_oversized_payloads(self) -> None:
        # Malformed JSON
        with self.assertRaises(NewsCalendarParseError):
            load_calendar_json("{not valid json")

        # Empty payload
        with self.assertRaises(NewsCalendarParseError):
            load_calendar_json("   ")

        # Oversized payload (> 2 MB)
        oversized = "{" + (" " * (MAX_CALENDAR_PAYLOAD_BYTES + 16)) + "}"
        with self.assertRaises(NewsCalendarParseError):
            load_calendar_json(oversized)

        # Naive timestamp (no Z or offset)
        naive_payload = json.dumps(
            {
                "events": [
                    {
                        "event_id": "naive-1",
                        "title": "US CPI",
                        "currency": "USD",
                        "impact": "HIGH",
                        "scheduled_utc": "2026-11-20T13:30:00",
                        "category": "CPI",
                    }
                ]
            }
        )
        with self.assertRaises(NewsCalendarParseError):
            load_calendar_json(naive_payload)

        # Date-only string
        date_only = json.dumps(
            [
                {
                    "event_id": "date-only",
                    "title": "US CPI",
                    "currency": "USD",
                    "impact": "HIGH",
                    "scheduled_utc": "2026-11-20",
                }
            ]
        )
        with self.assertRaises(NewsCalendarParseError):
            load_calendar_json(date_only)

        # Invalid impact
        bad_impact = json.dumps(
            [
                {
                    "event_id": "bad-imp",
                    "title": "US CPI",
                    "currency": "USD",
                    "impact": "EXTREME",
                    "scheduled_utc": "2026-11-20T13:30:00Z",
                }
            ]
        )
        with self.assertRaises(NewsCalendarParseError):
            load_calendar_json(bad_impact)

        # Invalid currency
        bad_currency = json.dumps(
            [
                {
                    "event_id": "bad-ccy",
                    "title": "US CPI",
                    "currency": "DOLLAR",
                    "impact": "HIGH",
                    "scheduled_utc": "2026-11-20T13:30:00Z",
                }
            ]
        )
        with self.assertRaises(NewsCalendarParseError):
            load_calendar_json(bad_currency)

        # Duplicate event IDs
        dup_ids = json.dumps(
            [
                {
                    "event_id": "dup-1",
                    "title": "US CPI",
                    "currency": "USD",
                    "impact": "HIGH",
                    "scheduled_utc": "2026-11-20T13:30:00Z",
                },
                {
                    "event_id": "dup-1",
                    "title": "US Core CPI",
                    "currency": "USD",
                    "impact": "HIGH",
                    "scheduled_utc": "2026-11-20T13:30:00Z",
                },
            ]
        )
        with self.assertRaises(NewsCalendarParseError):
            load_calendar_json(dup_ids)

    def test_stale_calendar_fail_closed_blocks_entries_but_allows_protective_actions(self) -> None:
        updated_at = _utc(2026, 11, 19, 0, 0, 0)
        shield = NewsShockShield(
            [],
            fail_closed_on_stale_calendar=True,
            max_calendar_age_hours=6.0,
            calendar_updated_at_utc=updated_at,
        )

        # Fresh at +5h -> entries allowed
        fresh_ts = updated_at + timedelta(hours=5)
        d_fresh = shield.evaluate("NAS100", TradeActionType.OPEN_NEW, now_utc=fresh_ts)
        self.assertTrue(d_fresh.allowed)
        self.assertEqual(d_fresh.reason_code, "ALLOWED_NO_ACTIVE_NEWS")

        # Stale at +6h01s -> OPEN_NEW and ADD_POSITION blocked with CALENDAR_STALE_FAIL_CLOSED
        stale_ts = updated_at + timedelta(hours=6, seconds=1)
        for entry_action in (TradeActionType.OPEN_NEW, TradeActionType.ADD_POSITION):
            d_stale = shield.evaluate("NAS100", entry_action, now_utc=stale_ts)
            self.assertFalse(d_stale.allowed)
            self.assertEqual(d_stale.reason_code, "CALENDAR_STALE_FAIL_CLOSED")
            self.assertIsNone(d_stale.resume_at_utc)

        # CRITICAL: All 5 protective actions remain ALLOWED even when calendar is stale!
        for prot_action in PROTECTIVE_ACTIONS:
            d_prot = shield.evaluate("NAS100", prot_action, now_utc=stale_ts)
            self.assertTrue(d_prot.allowed)
            self.assertEqual(d_prot.reason_code, "PROTECTIVE_ACTION_ALWAYS_ALLOWED")

        # Missing calendar_updated_at_utc with fail_closed_on_stale_calendar=True also fails closed
        no_ts_shield = NewsShockShield([], fail_closed_on_stale_calendar=True, max_calendar_age_hours=6.0)
        d_missing = no_ts_shield.evaluate("EUR_USD", TradeActionType.OPEN_NEW, now_utc=stale_ts)
        self.assertFalse(d_missing.allowed)
        self.assertEqual(d_missing.reason_code, "CALENDAR_STALE_FAIL_CLOSED")
        d_missing_prot = no_ts_shield.evaluate("EUR_USD", TradeActionType.EMERGENCY_CLOSE_ALL, now_utc=stale_ts)
        self.assertTrue(d_missing_prot.allowed)
        self.assertEqual(d_missing_prot.reason_code, "PROTECTIVE_ACTION_ALWAYS_ALLOWED")

    def test_pluggable_transport_and_ssrf_url_guard(self) -> None:
        class _StaticTransport:
            def fetch_calendar_json(self) -> str:
                return json.dumps(
                    {
                        "generated_at_utc": "2026-11-20T12:00:00Z",
                        "source": "static_transport",
                        "events": [
                            {
                                "event_id": "pce-1",
                                "title": "US Core PCE",
                                "currency": "USD",
                                "impact": "HIGH",
                                "scheduled_utc": "2026-11-20T13:30:00Z",
                                "category": "PCE",
                            }
                        ],
                    }
                )

        shield = NewsShockShield(transport=_StaticTransport())
        self.assertEqual(len(shield.events), 0)
        cal = shield.refresh_from_transport(now_utc=_utc(2026, 11, 20, 12, 1, 0))
        self.assertEqual(len(cal), 1)
        self.assertEqual(shield.calendar_updated_at_utc, _utc(2026, 11, 20, 12, 0, 0))
        self.assertFalse(
            shield.evaluate("XAUUSD", TradeActionType.OPEN_NEW, now_utc=_utc(2026, 11, 20, 13, 30, 0)).allowed
        )

        # Offline URL validator SSRF guard checks
        self.assertEqual(
            validate_https_calendar_url("https://calendar.example.com/v1/events.json"),
            "https://calendar.example.com/v1/events.json",
        )
        for bad_url in (
            "http://calendar.example.com/events.json",
            "file:///etc/passwd",
            "https://localhost/events.json",
            "https://127.0.0.1/events.json",
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.5/events.json",
            "https://[::1]/events.json",
            "https://user:secret@calendar.example.com/events.json",
        ):
            with self.assertRaises(NewsCalendarParseError, msg=f"Should reject {bad_url}"):
                validate_https_calendar_url(bad_url)


class TestSnapshotAndPreSliceGuard(unittest.TestCase):
    def test_shield_status_snapshot_read_only_and_countdowns(self) -> None:
        cpi_time = _utc(2026, 11, 20, 13, 30, 0)
        ecb_time = _utc(2026, 11, 20, 14, 15, 0)
        cpi = _event("cpi-1", "US CPI YoY", "USD", NewsImpact.HIGH, cpi_time, category="CPI")
        ecb = _event("ecb-1", "ECB Rate Decision", "EUR", NewsImpact.HIGH, ecb_time, category="ECB")
        updated = _utc(2026, 11, 20, 12, 0, 0)

        shield = NewsShockShield([cpi, ecb], calendar_updated_at_utc=updated)

        # 1) Clear state with upcoming blackout countdown (13:15:00Z -> CPI blackout starts 13:25:00Z = 600s)
        t_clear = _utc(2026, 11, 20, 13, 15, 0)
        snap_before = shield.shield_status_snapshot(["NAS100", "EUR_USD", "EUR_GBP"], now_utc=t_clear)
        # Verify JSON serializability and deterministic read-only repeatability
        serialized = json.dumps(snap_before)
        self.assertIsInstance(serialized, str)
        snap_repeat = shield.shield_status_snapshot(["NAS100", "EUR_USD", "EUR_GBP"], now_utc=t_clear)
        self.assertEqual(snap_before, snap_repeat)

        self.assertEqual(snap_before["overall_status"], "CLEAR")
        self.assertTrue(snap_before["protective_actions_always_allowed"])
        self.assertFalse(snap_before["calendar_stale"])
        self.assertTrue(snap_before["symbols"]["NAS100"]["new_entries_allowed"])
        self.assertEqual(snap_before["symbols"]["NAS100"]["next_upcoming_event"]["seconds_until_blackout_start"], 600)
        self.assertEqual(snap_before["symbols"]["NAS100"]["next_upcoming_event"]["seconds_until_event"], 900)
        self.assertEqual(snap_before["symbols"]["EUR_GBP"]["next_upcoming_event"]["event_id"], "ecb-1")
        self.assertEqual(len(snap_before["upcoming_blackouts"]), 2)

        # 2) Active CPI blackout at 13:31:00Z -> 240s until resume (13:35:00Z)
        t_active = _utc(2026, 11, 20, 13, 31, 0)
        snap_active = shield.shield_status_snapshot(["NAS100", "EUR_GBP"], now_utc=t_active)
        self.assertEqual(snap_active["overall_status"], "PAUSED_NEWS_WINDOW")
        self.assertFalse(snap_active["symbols"]["NAS100"]["new_entries_allowed"])
        self.assertTrue(snap_active["symbols"]["NAS100"]["protective_actions_allowed"])
        self.assertEqual(snap_active["symbols"]["NAS100"]["seconds_until_resume"], 240)
        self.assertEqual(snap_active["symbols"]["NAS100"]["resume_at_utc"], "2026-11-20T13:35:00Z")
        self.assertIn("US CPI YoY", snap_active["symbols"]["NAS100"]["plain_english_status"])
        self.assertTrue(snap_active["symbols"]["EUR_GBP"]["new_entries_allowed"])

    def test_pre_slice_guard_and_immutability(self) -> None:
        @dataclass(frozen=True)
        class _DummySlice:
            symbol: str

        cpi_time = _utc(2026, 11, 20, 13, 30, 0)
        cpi = _event("cpi-guard", "US CPI", "USD", NewsImpact.HIGH, cpi_time, category="CPI")
        shield = NewsShockShield([cpi])

        guard_blocked = shield.make_pre_slice_guard(clock=lambda: cpi_time)
        self.assertEqual(guard_blocked(_DummySlice(symbol="NAS100")), (False, "NEW_ENTRY_PAUSED_NEWS_WINDOW"))
        self.assertEqual(guard_blocked({"symbol": "EUR_GBP"}), (True, "ALLOWED_NO_ACTIVE_NEWS"))

        guard_clear = shield.make_pre_slice_guard(clock=lambda: cpi_time - timedelta(minutes=10))
        self.assertEqual(guard_clear("NAS100"), (True, "ALLOWED_NO_ACTIVE_NEWS"))

        # Frozen immutability & naive datetime rejection
        dec = shield.evaluate("NAS100", TradeActionType.OPEN_NEW, now_utc=cpi_time)
        self.assertIsInstance(dec, NewsShieldDecision)
        with self.assertRaises(FrozenInstanceError):
            dec.allowed = True  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            cpi.currency = "EUR"  # type: ignore[misc]
        with self.assertRaises(ValueError):
            shield.evaluate("NAS100", TradeActionType.OPEN_NEW, now_utc=datetime(2026, 11, 20, 13, 30, 0))
        with self.assertRaises(TypeError):
            shield.evaluate("NAS100", "OPEN_NEW", now_utc=cpi_time)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
