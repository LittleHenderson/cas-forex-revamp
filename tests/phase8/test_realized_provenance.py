"""Unit tests for Broker-Attributed Realized P/L Provenance & Live Trading Status Engine."""

from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import unittest
from zoneinfo import ZoneInfo

from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.treasury.realized_provenance import (
    PROVENANCE_SCHEMA,
    SESSION_ASIA,
    SESSION_LONDON,
    SESSION_NEW_YORK,
    STATE_ACTIVE_SCANNING,
    STATE_PAUSED_RESEARCH_RESPITE,
    STATE_PAUSED_SAFETY_LOCK,
    STATE_TRADING_NOW,
    _PACIFIC_FALLBACK_TZ,
    build_realized_provenance,
    classify_trading_session,
    format_broker_label,
    format_dual_timestamp,
    is_synthetic_sweep,
)


class BrokerLabelAndSyntheticTests(unittest.TestCase):
    def test_format_broker_label_known_brokers(self) -> None:
        self.assertEqual(format_broker_label("LHFX_MT5"), "LHFX")
        self.assertEqual(format_broker_label("LHFX"), "LHFX")
        self.assertEqual(format_broker_label("LHFX_DEMO"), "LHFX")
        self.assertEqual(format_broker_label("LHFX_LIVE"), "LHFX")
        self.assertEqual(format_broker_label("lhfx_mt5"), "LHFX")

        self.assertEqual(format_broker_label("HUGOSWAY_MT5"), "Hugo's Way")
        self.assertEqual(format_broker_label("HUGOSWAY"), "Hugo's Way")
        self.assertEqual(format_broker_label("HUGOS_WAY"), "Hugo's Way")
        self.assertEqual(format_broker_label("hugosway_mt5"), "Hugo's Way")

        self.assertEqual(format_broker_label("OANDA_PRACTICE"), "OANDA")
        self.assertEqual(format_broker_label("OANDA_LIVE"), "OANDA")
        self.assertEqual(format_broker_label("OANDA"), "OANDA")
        self.assertEqual(format_broker_label("oanda_practice"), "OANDA")

    def test_format_broker_label_synthetic_and_fallback(self) -> None:
        for marker in (
            "SESSION_SYNC",
            "SESSION_BASKET",
            "RECONCILIATION",
            "PORTFOLIO_RECONCILE",
            "DUAL_SHIELD_BARBELL",
        ):
            self.assertEqual(format_broker_label(marker), "Internal Reconciliation")
        self.assertEqual(format_broker_label(""), "Unknown Broker")
        self.assertEqual(format_broker_label("   "), "Unknown Broker")
        self.assertEqual(format_broker_label("CUSTOM_ECN"), "CUSTOM_ECN")

    def test_is_synthetic_sweep_detection(self) -> None:
        synthetic_rows = [
            {
                "trade_id": "SESSION_SYNC_2026-11-20_0001_50000",
                "symbol": "SESSION_BASKET",
                "broker_id": "DUAL_SHIELD_BARBELL",
            },
            {
                "trade_id": "tkt-sync-1",
                "symbol": "SESSION_BASKET",
                "broker_id": "LHFX_MT5",
            },
            {
                "trade_id": "RECONCILIATION_001",
                "symbol": "NAS100",
                "broker_id": "LHFX_MT5",
            },
            {
                "trade_id": "tkt-99",
                "symbol": "PORTFOLIO_RECONCILE",
                "broker_id": "HUGOSWAY_MT5",
            },
            {
                "trade_id": "tkt-100",
                "symbol": "NAS100",
                "broker_id": "PORTFOLIO_RECONCILE",
            },
            {
                "trade_id": "tkt-101",
                "symbol": "",
                "broker_id": "LHFX_MT5",
            },
            {
                "trade_id": "tkt-102",
                "symbol": "US30",
                "broker_id": "OANDA_PRACTICE",
                "is_synthetic": True,
            },
        ]
        for row in synthetic_rows:
            self.assertTrue(is_synthetic_sweep(row), msg=f"Expected synthetic: {row}")

        real_rows = [
            {"trade_id": "mt5-1001", "symbol": "NAS100", "broker_id": "LHFX_MT5"},
            {"trade_id": "mt5-1002", "symbol": "US30", "broker_id": "HUGOSWAY_MT5"},
            {"trade_id": "oanda-55", "symbol": "EUR/USD", "broker_id": "OANDA_PRACTICE"},
            {"trade_id": "manual-7", "symbol": "XAUUSD", "broker_id": "DUAL_SHIELD"},
        ]
        for row in real_rows:
            self.assertFalse(is_synthetic_sweep(row), msg=f"Expected real: {row}")


class SessionClassificationTests(unittest.TestCase):
    def test_exact_three_region_boundaries(self) -> None:
        cases = [
            (datetime(2026, 11, 20, 21, 59, 59, tzinfo=timezone.utc), SESSION_NEW_YORK, "New York / US"),
            (datetime(2026, 11, 20, 22, 0, 0, tzinfo=timezone.utc), SESSION_ASIA, "Asia / Tokyo–Sydney"),
            (datetime(2026, 11, 20, 0, 0, 0, tzinfo=timezone.utc), SESSION_ASIA, "Asia / Tokyo–Sydney"),
            (datetime(2026, 11, 20, 6, 59, 59, tzinfo=timezone.utc), SESSION_ASIA, "Asia / Tokyo–Sydney"),
            (datetime(2026, 11, 20, 7, 0, 0, tzinfo=timezone.utc), SESSION_LONDON, "London"),
            (datetime(2026, 11, 20, 11, 59, 59, tzinfo=timezone.utc), SESSION_LONDON, "London"),
            (datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc), SESSION_NEW_YORK, "New York / US"),
            (datetime(2026, 11, 20, 16, 30, 0, tzinfo=timezone.utc), SESSION_NEW_YORK, "New York / US"),
        ]
        for ts, expected_id, expected_label in cases:
            out = classify_trading_session(ts)
            self.assertEqual(out["session_id"], expected_id, msg=f"Failed for {ts.isoformat()}")
            self.assertEqual(out["session_label"], expected_label, msg=f"Failed for {ts.isoformat()}")

    def test_rejects_naive_and_non_utc_datetimes(self) -> None:
        with self.assertRaises(ContractError):
            classify_trading_session(datetime(2026, 11, 20, 8, 0, 0))
        with self.assertRaises(ContractError):
            classify_trading_session(
                datetime(2026, 11, 20, 0, 0, 0, tzinfo=timezone(timedelta(hours=-8)))
            )
        with self.assertRaises(ContractError):
            classify_trading_session("2026-11-20T08:00:00")


class DualTimestampFormattingTests(unittest.TestCase):
    def test_standard_time_pst(self) -> None:
        ts = datetime(2026, 11, 20, 8, 41, 12, tzinfo=timezone.utc)
        out = format_dual_timestamp(ts)
        self.assertEqual(out["occurred_at_utc"], "2026-11-20T08:41:12Z")
        self.assertEqual(out["utc_display"], "2026-11-20 08:41:12 UTC")
        self.assertEqual(out["date_pt"], "2026-11-20")
        self.assertEqual(out["time_pt"], "12:41:12 AM PT")
        self.assertEqual(out["local_display"], "Nov 20, 2026 · 12:41:12 AM PT")
        self.assertEqual(out["tz_abbr"], "PST")

    def test_daylight_saving_time_pdt(self) -> None:
        ts = datetime(2026, 7, 15, 19, 5, 9, tzinfo=timezone.utc)
        out = format_dual_timestamp(ts)
        self.assertEqual(out["occurred_at_utc"], "2026-07-15T19:05:09Z")
        self.assertEqual(out["utc_display"], "2026-07-15 19:05:09 UTC")
        self.assertEqual(out["date_pt"], "2026-07-15")
        self.assertEqual(out["time_pt"], "12:05:09 PM PT")
        self.assertEqual(out["local_display"], "Jul 15, 2026 · 12:05:09 PM PT")
        self.assertEqual(out["tz_abbr"], "PDT")

    def test_utc_to_pt_previous_calendar_day(self) -> None:
        ts = datetime(2026, 11, 20, 3, 15, 0, tzinfo=timezone.utc)
        out = format_dual_timestamp(ts)
        self.assertEqual(out["date_pt"], "2026-11-19")
        self.assertEqual(out["time_pt"], "7:15:00 PM PT")
        self.assertEqual(out["local_display"], "Nov 19, 2026 · 7:15:00 PM PT")
        self.assertEqual(out["utc_display"], "2026-11-20 03:15:00 UTC")

    def test_pacific_fallback_matches_zoneinfo_across_dst_boundaries(self) -> None:
        iana_la = ZoneInfo("America/Los_Angeles")
        probes = [
            datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 3, 8, 9, 59, 59, tzinfo=timezone.utc),   # 1 sec before spring forward
            datetime(2026, 3, 8, 10, 0, 0, tzinfo=timezone.utc),    # exact spring forward -> PDT
            datetime(2026, 7, 15, 19, 5, 9, tzinfo=timezone.utc),   # mid-summer PDT
            datetime(2026, 11, 1, 8, 30, 0, tzinfo=timezone.utc),   # 1:30 AM PDT (first pass)
            datetime(2026, 11, 1, 9, 30, 0, tzinfo=timezone.utc),   # 1:30 AM PST (second pass fold=1)
            datetime(2026, 11, 20, 8, 41, 12, tzinfo=timezone.utc), # standard PST
        ]
        for ts in probes:
            from_iana = format_dual_timestamp(ts, pacific_tz=iana_la)
            from_fallback = format_dual_timestamp(ts, pacific_tz=_PACIFIC_FALLBACK_TZ)
            self.assertEqual(from_fallback, from_iana, msg=f"Mismatch at {ts.isoformat()}")

    def test_rejects_naive_datetime(self) -> None:
        with self.assertRaises(ContractError):
            format_dual_timestamp(datetime(2026, 11, 20, 8, 41, 12))


class RealizedProvenanceEngineTests(unittest.TestCase):
    def test_multi_broker_multi_session_and_synthetic_exclusion(self) -> None:
        sweeps = [
            {
                "trade_id": "lhfx-001",
                "symbol": "NAS100",
                "broker_id": "LHFX_MT5",
                "realized_net_usd": "412.50",
                "retained_trading_usd": "206.25",
                "bank_sweep_usd": "206.25",
                "occurred_at": "2026-11-20T02:15:00Z",  # ASIA
            },
            {
                "trade_id": "hugo-002",
                "symbol": "US30",
                "broker_id": "HUGOSWAY_MT5",
                "realized_net_usd": "285.75",
                "retained_trading_usd": "142.88",
                "bank_sweep_usd": "142.87",
                "occurred_at": "2026-11-20T08:41:12Z",  # LONDON
            },
            {
                "trade_id": "oanda-003",
                "symbol": "EUR/USD",
                "broker_id": "OANDA_PRACTICE",
                "realized_net_usd": "-45.25",
                "retained_trading_usd": "-45.25",
                "bank_sweep_usd": "0.00",
                "occurred_at": "2026-11-20T14:20:05Z",  # NEW_YORK
            },
            {
                "trade_id": "lhfx-004",
                "symbol": "NAS100",
                "broker_id": "LHFX_MT5",
                "realized_net_usd": "120.125",
                "retained_trading_usd": "60.0625",
                "bank_sweep_usd": "60.0625",
                "occurred_at": "2026-11-20T15:05:30Z",  # NEW_YORK (newest REAL trade)
            },
            # Newer synthetic SESSION_SYNC row MUST NOT hijack last_real_trade or markets/brokers
            {
                "trade_id": "SESSION_SYNC_2026-11-20_0001_10000",
                "symbol": "SESSION_BASKET",
                "broker_id": "DUAL_SHIELD_BARBELL",
                "realized_net_usd": "100.00",
                "retained_trading_usd": "100.00",
                "bank_sweep_usd": "0.00",
                "occurred_at": "2026-11-20T16:00:00Z",
            },
            {
                "trade_id": "PORTFOLIO_RECONCILE_2026-11-20",
                "symbol": "RECONCILIATION",
                "broker_id": "RECONCILIATION",
                "realized_net_usd": "-12.50",
                "retained_trading_usd": "-12.50",
                "bank_sweep_usd": "0.00",
                "occurred_at": "2026-11-20T16:05:00Z",
            },
        ]

        now = datetime(2026, 11, 20, 16, 10, 0, tzinfo=timezone.utc)
        res = build_realized_provenance(
            sweeps,
            open_positions=[
                {"ticket": "p1", "symbol": "NAS100", "broker_id": "LHFX_MT5"},
                {"ticket": "p2", "symbol": "US30", "broker_id": "HUGOSWAY_MT5"},
            ],
            now_utc=now,
        )

        self.assertEqual(res["schema"], PROVENANCE_SCHEMA)
        # Ensure clean JSON serialization
        encoded = json.dumps(res)
        self.assertIn("Hugo's Way", encoded)

        # Live status
        live = res["live_trading_status"]
        self.assertTrue(live["is_currently_trading"])
        self.assertEqual(live["state_code"], STATE_TRADING_NOW)
        self.assertEqual(live["headline"], "TRADING NOW — 2 OPEN TRADES: NAS100, US30")
        self.assertEqual(live["open_position_count"], 2)
        self.assertEqual(live["open_markets"], ["NAS100", "US30"])
        self.assertEqual(live["open_brokers"], ["LHFX", "Hugo's Way"])

        # Last real trade MUST be lhfx-004, NOT the newer SESSION_SYNC/RECONCILE rows
        last = res["last_real_trade"]
        self.assertIsNotNone(last)
        self.assertEqual(last["trade_id"], "lhfx-004")
        self.assertEqual(last["symbol"], "NAS100")
        self.assertEqual(last["broker_id"], "LHFX_MT5")
        self.assertEqual(last["broker_label"], "LHFX")
        self.assertEqual(last["realized_net_usd"], "120.125")
        self.assertEqual(last["occurred_at_utc"], "2026-11-20T15:05:30Z")
        self.assertEqual(last["utc_display"], "2026-11-20 15:05:30 UTC")
        self.assertEqual(last["date_pt"], "2026-11-20")
        self.assertEqual(last["time_pt"], "7:05:30 AM PT")
        self.assertEqual(last["local_display"], "Nov 20, 2026 · 7:05:30 AM PT")
        self.assertEqual(last["session_id"], SESSION_NEW_YORK)
        self.assertEqual(last["session_label"], "New York / US")

        # realized_entries: 4 real trades newest first, 0 synthetic rows
        entries = res["realized_entries"]
        self.assertEqual([e["trade_id"] for e in entries], ["lhfx-004", "oanda-003", "hugo-002", "lhfx-001"])
        self.assertTrue(all(e["symbol"] != "SESSION_BASKET" for e in entries))

        # by_market sorted by abs(total_realized_usd) desc: NAS100 (532.625), US30 (285.75), EUR/USD (-45.25)
        by_market = res["by_market"]
        self.assertEqual([m["symbol"] for m in by_market], ["NAS100", "US30", "EUR/USD"])
        self.assertEqual(by_market[0]["total_realized_usd"], "532.625")
        self.assertEqual(by_market[0]["trade_count"], 2)
        self.assertEqual(by_market[0]["win_count"], 2)
        self.assertEqual(by_market[0]["loss_count"], 0)
        self.assertEqual(by_market[0]["brokers"], ["LHFX"])
        self.assertEqual(by_market[0]["sessions"], ["Asia / Tokyo–Sydney", "New York / US"])
        self.assertEqual(by_market[0]["last_occurred_at_utc"], "2026-11-20T15:05:30Z")
        self.assertEqual(by_market[0]["last_session_label"], "New York / US")

        self.assertEqual(by_market[2]["total_realized_usd"], "-45.25")
        self.assertEqual(by_market[2]["win_count"], 0)
        self.assertEqual(by_market[2]["loss_count"], 1)
        self.assertEqual(by_market[2]["brokers"], ["OANDA"])

        # by_broker: LHFX (532.625), Hugo's Way (285.75), OANDA (-45.25)
        by_broker = res["by_broker"]
        self.assertEqual([b["broker_label"] for b in by_broker], ["LHFX", "Hugo's Way", "OANDA"])
        self.assertEqual([b["broker_id"] for b in by_broker], ["LHFX_MT5", "HUGOSWAY_MT5", "OANDA_PRACTICE"])
        self.assertEqual(by_broker[0]["total_realized_usd"], "532.625")
        self.assertEqual(by_broker[1]["total_realized_usd"], "285.75")
        self.assertEqual(by_broker[1]["markets"], ["US30"])
        self.assertEqual(by_broker[1]["sessions"], ["London"])
        self.assertEqual(by_broker[2]["total_realized_usd"], "-45.25")

        # by_session in canonical order: ASIA (412.50), LONDON (285.75), NEW_YORK (74.875)
        by_session = res["by_session"]
        self.assertEqual([s["session_id"] for s in by_session], [SESSION_ASIA, SESSION_LONDON, SESSION_NEW_YORK])
        self.assertEqual(by_session[0]["total_realized_usd"], "412.50")
        self.assertEqual(by_session[1]["total_realized_usd"], "285.75")
        self.assertEqual(by_session[2]["total_realized_usd"], "74.875")
        self.assertEqual(by_session[2]["brokers"], ["LHFX", "OANDA"])
        self.assertEqual(by_session[2]["markets"], ["EUR/USD", "NAS100"])

        # Exact Decimal reconciliation
        totals = res["totals"]
        self.assertEqual(totals["real_trade_realized_usd"], "773.125")
        self.assertEqual(totals["synthetic_adjustment_usd"], "87.50")
        self.assertEqual(totals["combined_total_realized_usd"], "860.625")
        self.assertEqual(totals["real_trade_count"], 4)
        self.assertEqual(totals["synthetic_row_count"], 2)
        self.assertEqual(
            Decimal(totals["real_trade_realized_usd"]) + Decimal(totals["synthetic_adjustment_usd"]),
            Decimal(totals["combined_total_realized_usd"]),
        )

    def test_all_four_live_trading_states(self) -> None:
        now = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)

        # 1. TRADING_NOW (single open trade)
        s1 = build_realized_provenance(
            [],
            open_positions=[{"symbol": "XAUUSD", "broker_id": "HUGOSWAY_MT5"}],
            now_utc=now,
        )["live_trading_status"]
        self.assertTrue(s1["is_currently_trading"])
        self.assertEqual(s1["state_code"], STATE_TRADING_NOW)
        self.assertEqual(s1["headline"], "TRADING NOW — 1 OPEN TRADE: XAUUSD")
        self.assertEqual(s1["open_markets"], ["XAUUSD"])
        self.assertEqual(s1["open_brokers"], ["Hugo's Way"])

        # 2. ACTIVE_SCANNING
        s2 = build_realized_provenance(
            [],
            open_positions=[],
            operating_mode="ACTIVE_TRADING",
            governance_mode="ACTIVE",
            effective_status="ACTIVE",
            now_utc=now,
        )["live_trading_status"]
        self.assertFalse(s2["is_currently_trading"])
        self.assertEqual(s2["state_code"], STATE_ACTIVE_SCANNING)
        self.assertEqual(s2["open_position_count"], 0)
        self.assertIn("SCANNING", s2["headline"])

        # 3. PAUSED_RESEARCH_RESPITE
        s3 = build_realized_provenance(
            [],
            open_positions=[],
            operating_mode="RESEARCH_RESPITE",
            governance_mode="ACTIVE",
            effective_status="DAILY_QUOTA_LOCKED",
            now_utc=now,
        )["live_trading_status"]
        self.assertFalse(s3["is_currently_trading"])
        self.assertEqual(s3["state_code"], STATE_PAUSED_RESEARCH_RESPITE)
        self.assertIn("RESEARCH RESPITE", s3["headline"])

        s3b = build_realized_provenance(
            [],
            open_positions=[],
            operating_mode="ACTIVE_TRADING",
            governance_mode="ACTIVE",
            effective_status="PROFIT_FLOOR_LOCKED",
            now_utc=now,
        )["live_trading_status"]
        self.assertEqual(s3b["state_code"], STATE_PAUSED_RESEARCH_RESPITE)

        # 4. PAUSED_SAFETY_LOCK (loss circuit, stopped, paused new risk)
        for op, gov, eff in (
            ("ACTIVE_TRADING", "ACTIVE", "DAILY_LOSS_CIRCUIT_TRIPPED"),
            ("ACTIVE_TRADING", "STOPPED", "STOPPED"),
            ("ACTIVE_TRADING", "PAUSED_NEW_RISK", "PAUSED_NEW_RISK"),
            ("RESEARCH_RESPITE", "STOPPED", "STOPPED"),
        ):
            s4 = build_realized_provenance(
                [],
                open_positions=[],
                operating_mode=op,
                governance_mode=gov,
                effective_status=eff,
                now_utc=now,
            )["live_trading_status"]
            self.assertFalse(s4["is_currently_trading"])
            self.assertEqual(s4["state_code"], STATE_PAUSED_SAFETY_LOCK)
            self.assertIn("SAFETY LOCK", s4["headline"])

    def test_empty_and_synthetic_only_inputs(self) -> None:
        now = datetime(2026, 11, 20, 8, 0, 0, tzinfo=timezone.utc)
        empty = build_realized_provenance([], now_utc=now)
        self.assertIsNone(empty["last_real_trade"])
        self.assertEqual(empty["realized_entries"], [])
        self.assertEqual(empty["by_market"], [])
        self.assertEqual(empty["by_broker"], [])
        self.assertEqual(empty["by_session"], [])
        self.assertEqual(
            empty["totals"],
            {
                "real_trade_realized_usd": "0.00",
                "synthetic_adjustment_usd": "0.00",
                "combined_total_realized_usd": "0.00",
                "real_trade_count": 0,
                "synthetic_row_count": 0,
            },
        )

        syn_only = build_realized_provenance(
            [
                {
                    "trade_id": "SESSION_SYNC_2026-11-20_0001_25000",
                    "symbol": "SESSION_BASKET",
                    "broker_id": "DUAL_SHIELD_BARBELL",
                    "realized_net_usd": "250.00",
                    "occurred_at": "2026-11-20T07:30:00Z",
                }
            ],
            now_utc=now,
        )
        self.assertIsNone(syn_only["last_real_trade"])
        self.assertEqual(syn_only["realized_entries"], [])
        self.assertEqual(syn_only["by_market"], [])
        self.assertEqual(syn_only["by_broker"], [])
        self.assertEqual(syn_only["by_session"], [])
        self.assertEqual(syn_only["totals"]["real_trade_realized_usd"], "0.00")
        self.assertEqual(syn_only["totals"]["synthetic_adjustment_usd"], "250.00")
        self.assertEqual(syn_only["totals"]["combined_total_realized_usd"], "250.00")
        self.assertEqual(syn_only["totals"]["real_trade_count"], 0)
        self.assertEqual(syn_only["totals"]["synthetic_row_count"], 1)

    def test_exact_decimal_no_rounding_and_float_rejection(self) -> None:
        now = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
        sweeps = [
            {
                "trade_id": "d1",
                "symbol": "EUR/USD",
                "broker_id": "OANDA_PRACTICE",
                "realized_net_usd": Decimal("0.10"),
                "occurred_at": "2026-11-20T12:01:00Z",
            },
            {
                "trade_id": "d2",
                "symbol": "EUR/USD",
                "broker_id": "OANDA_PRACTICE",
                "realized_net_usd": Decimal("0.20"),
                "occurred_at": "2026-11-20T12:02:00Z",
            },
            {
                "trade_id": "d3",
                "symbol": "EUR/USD",
                "broker_id": "OANDA_PRACTICE",
                "realized_net_usd": "-0.0005",
                "occurred_at": "2026-11-20T12:03:00Z",
            },
            {
                "trade_id": "d4",
                "symbol": "EUR/USD",
                "broker_id": "OANDA_PRACTICE",
                "realized_net_usd": "0.00",
                "occurred_at": "2026-11-20T12:04:00Z",
            },
        ]
        res = build_realized_provenance(sweeps, now_utc=now)
        self.assertEqual(res["totals"]["real_trade_realized_usd"], "0.2995")
        self.assertEqual(res["by_market"][0]["win_count"], 2)
        self.assertEqual(res["by_market"][0]["loss_count"], 1)
        self.assertEqual(res["by_market"][0]["trade_count"], 4)

        # Reject float money
        with self.assertRaises(ContractError):
            build_realized_provenance(
                [
                    {
                        "trade_id": "bad-float",
                        "symbol": "NAS100",
                        "broker_id": "LHFX_MT5",
                        "realized_net_usd": 12.34,
                        "occurred_at": "2026-11-20T12:00:00Z",
                    }
                ],
                now_utc=now,
            )

        # Reject bool money
        with self.assertRaises(ContractError):
            build_realized_provenance(
                [
                    {
                        "trade_id": "bad-bool",
                        "symbol": "NAS100",
                        "broker_id": "LHFX_MT5",
                        "realized_net_usd": True,
                        "occurred_at": "2026-11-20T12:00:00Z",
                    }
                ],
                now_utc=now,
            )

    def test_source_file_hygiene_zero_assert_lf_no_bom(self) -> None:
        src_file = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "cas_forex_revamp"
            / "treasury"
            / "realized_provenance.py"
        )
        raw = src_file.read_bytes()
        self.assertFalse(raw.startswith(bytes([0xEF, 0xBB, 0xBF])), "UTF-8 BOM is forbidden")
        self.assertNotIn(bytes([0x0D]), raw, "CRLF/CR line endings are forbidden")
        tree = ast.parse(raw.decode("utf-8"))
        assert_nodes = [n for n in ast.walk(tree) if isinstance(n, ast.Assert)]
        self.assertEqual(assert_nodes, [], "Bandit B101: assert is forbidden in src/")


if __name__ == "__main__":
    unittest.main()
