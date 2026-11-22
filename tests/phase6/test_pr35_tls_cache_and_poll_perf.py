"""Regression tests for PR #35 TLS context caching, fail-fast FX feed, index client, and router snapshot deduplication."""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest import mock

from cas_forex_revamp.composition import live_cockpit_server as cockpit_mod
from cas_forex_revamp.futures import tradovate_venue as tradovate_mod
from cas_forex_revamp.operator import frontier_backends as frontier_mod
from cas_forex_revamp.valve.tks_meta_valve_controller import PeakEquityStore, load_default_forex_valve_gate
from cas_forex_revamp.venue import dual_shield_router as router_mod
from cas_forex_revamp.venue import external_paper_broker as paper_mod
from cas_forex_revamp.venue import live_market_stream as stream_mod
from cas_forex_revamp.venue.dual_shield_router import (
    BarbellCapitalPolicy,
    DualShieldBrokerRouter,
    OandaQuoteTruthOracle,
)
from cas_forex_revamp.venue.external_paper_broker import OandaPracticePaperClient
from cas_forex_revamp.venue.live_market_stream import (
    ExpandedPublicLiveFxFeedClient,
    PinnedPublicHTTPSHandler,
    PublicUsIndexFeedClient,
    build_pinned_public_opener,
    get_cached_tls12_ssl_context,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    Mt5Credentials,
    Mt5MutationJournal,
    Mt5PaperBrokerVenue,
    Mt5SpoolBridgeTransport,
    OandaPracticeFallbackVenue,
    SimMt5SpoolEa,
)
from cas_forex_revamp.contracts import ContractError, decimal_text

D = Decimal
T0 = datetime(2026, 11, 21, 14, 0, 0, tzinfo=timezone.utc)


def _test_label(tag: str) -> str:
    return f"test-{tag}"


class Pr35TlsCacheAndFeedPerfTests(unittest.TestCase):
    def test_get_cached_tls12_ssl_context_reuses_and_respects_ca_env(self) -> None:
        # Also confirm all edited HTTPS client modules import cleanly together
        self.assertTrue(hasattr(cockpit_mod, "LoopbackCockpitServer"))
        self.assertTrue(hasattr(frontier_mod, "default_frontier_https_post"))
        self.assertTrue(hasattr(paper_mod, "OandaPracticePaperClient"))
        self.assertTrue(hasattr(tradovate_mod, "TradovateMicroFuturesVenue"))

        saved_env = {k: os.environ.get(k) for k in ("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE")}
        saved_cache = dict(stream_mod._TLS_CONTEXT_CACHE)
        created_contexts: list[mock.MagicMock] = []

        def _fake_create_default_context() -> mock.MagicMock:
            m = mock.MagicMock(spec=ssl.SSLContext)
            created_contexts.append(m)
            return m

        try:
            with tempfile.TemporaryDirectory() as ca_tmp:
                ca_one = str(Path(ca_tmp) / "ca-one.pem")
                ca_two = str(Path(ca_tmp) / "ca-two.pem")
                with stream_mod._TLS_CONTEXT_CACHE_LOCK:
                    stream_mod._TLS_CONTEXT_CACHE.clear()
                os.environ["SSL_CERT_FILE"] = ca_one
                os.environ.pop("SSL_CERT_DIR", None)
                os.environ.pop("REQUESTS_CA_BUNDLE", None)

                with mock.patch.object(stream_mod.ssl, "create_default_context", side_effect=_fake_create_default_context) as mk_ctx:
                    ctx1 = get_cached_tls12_ssl_context()
                    ctx2 = get_cached_tls12_ssl_context()
                    opener = build_pinned_public_opener()
                    handler = PinnedPublicHTTPSHandler()

                    self.assertIs(ctx1, ctx2)
                    self.assertEqual(ctx1.minimum_version, ssl.TLSVersion.TLSv1_2)
                    self.assertIs(handler._pinned_context, ctx1)
                    self.assertIsNotNone(opener)
                    self.assertEqual(mk_ctx.call_count, 1)

                    os.environ["SSL_CERT_FILE"] = ca_two
                    ctx3 = get_cached_tls12_ssl_context()
                    self.assertIsNot(ctx3, ctx1)
                    self.assertEqual(ctx3.minimum_version, ssl.TLSVersion.TLSv1_2)
                    self.assertEqual(mk_ctx.call_count, 2)

                    os.environ["SSL_CERT_FILE"] = ca_one
                    self.assertIs(get_cached_tls12_ssl_context(), ctx1)
                    self.assertEqual(mk_ctx.call_count, 2)
        finally:
            with stream_mod._TLS_CONTEXT_CACHE_LOCK:
                stream_mod._TLS_CONTEXT_CACHE.clear()
                stream_mod._TLS_CONTEXT_CACHE.update(saved_cache)
            for k, prev in saved_env.items():
                if prev is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = prev

    def test_public_us_index_feed_client_default_transport_delegates_to_https_get_pinned_host(self) -> None:
        client = PublicUsIndexFeedClient(timeout_seconds=7.5, max_wire_bytes=65536)
        sample_url = "https://query1.finance.yahoo.com/v8/finance/chart/%5ENDX?interval=1m&range=1d"
        sentinel = b'{"chart":{"result":[{"meta":{"regularMarketPrice":20500.0}}]}}'
        with mock.patch.object(stream_mod, "_https_get_pinned_host", return_value=sentinel) as get_mock:
            out = client._get(sample_url)
        self.assertEqual(out, sentinel)
        get_mock.assert_called_once_with(sample_url, timeout_seconds=7.5, max_bytes=65536)

    def test_fetch_market_stream_fails_fast_on_wide_spread_before_ohlc_fetches(self) -> None:
        calls: list[str] = []
        ecb_json = json.dumps({
            "date": "2026-11-20",
            "base": "EUR",
            "rates": {
                "USD": 1.1052,
                "GBP": 0.83559,
                "JPY": 176.83,
                "CHF": 0.9266,
                "AUD": 1.6288,
                "CAD": 1.5758,
                "NZD": 1.9978,
            },
        }).encode("utf-8")
        # Construct ticker where USDJPY has >300 bps spread (5.00 yen on ~160 = ~312.5 bps)
        ticker_json = json.dumps({
            "error": [],
            "result": {
                "ZEURZUSD": {"b": ["1.10510", "10", "10.0"], "a": ["1.10530", "10", "10.0"]},
                "ZGBPZUSD": {"b": ["1.32250", "10", "10.0"], "a": ["1.32280", "10", "10.0"]},
                "ZUSDZJPY": {"b": ["157.500", "10", "10.0"], "a": ["162.500", "10", "10.0"]},
                "USDCHF": {"b": ["0.83830", "10", "10.0"], "a": ["0.83850", "10", "10.0"]},
                "AUDUSD": {"b": ["0.67840", "10", "10.0"], "a": ["0.67860", "10", "10.0"]},
                "USDCAD": {"b": ["1.42570", "10", "10.0"], "a": ["1.42590", "10", "10.0"]},
                "EURGBP": {"b": ["0.83550", "10", "10.0"], "a": ["0.83570", "10", "10.0"]},
                "EURJPY": {"b": ["176.800", "10", "10.0"], "a": ["176.860", "10", "10.0"]},
                "EURCHF": {"b": ["0.92650", "10", "10.0"], "a": ["0.92670", "10", "10.0"]},
                "EURAUD": {"b": ["1.62860", "10", "10.0"], "a": ["1.62900", "10", "10.0"]},
                "EURCAD": {"b": ["1.57560", "10", "10.0"], "a": ["1.57600", "10", "10.0"]},
                "AUDJPY": {"b": ["119.950", "10", "10.0"], "a": ["120.050", "10", "10.0"]},
            },
        }).encode("utf-8")

        def _recording_get(url: str, _timeout: float, _max_bytes: int) -> bytes:
            calls.append(url)
            if "frankfurter" in url or "ecb.europa.eu" in url:
                return ecb_json
            if "/0/public/Ticker" in url:
                return ticker_json
            raise AssertionError(f"OHLC/Yahoo URL should not have been fetched on wide weekend spread: {url}")

        client = ExpandedPublicLiveFxFeedClient(http_get=_recording_get)
        with self.assertRaises(ContractError) as ctx:
            client.fetch_market_stream(now=T0)
        self.assertIn("USDJPY: spread", str(ctx.exception))
        self.assertEqual(len(calls), 2)

    def test_dual_shield_routing_snapshot_single_sync_and_equity_pass(self) -> None:
        quotes = {
            "EURUSD": (D("1.10000"), D("1.10010")),
            "GBPUSD": (D("1.26500"), D("1.26512")),
            "USDJPY": (D("150.100"), D("150.115")),
        }
        gate = load_default_forex_valve_gate()

        def _fake_oanda_http(method: str, url: str, _headers: dict[str, str], _body: bytes | None, _t: float, _m: int = 32768) -> bytes:
            if method == "GET" and url.endswith("/summary"):
                return json.dumps({
                    "account": {
                        "id": "101-001-7777777-001",
                        "currency": "USD",
                        "balance": "100000.00",
                        "NAV": "100000.00",
                        "unrealizedPL": "0.00",
                        "marginUsed": "0.00",
                        "marginAvailable": "100000.00",
                        "openTradeCount": 0,
                    }
                }).encode("utf-8")
            if method == "GET" and "/pricing" in url:
                return json.dumps({
                    "time": "2026-11-21T14:00:00Z",
                    "prices": [
                        {
                            "instrument": f"{sym[:3]}_{sym[3:]}",
                            "time": "2026-11-21T14:00:00.000000000Z",
                            "tradeable": True,
                            "bids": [{"price": decimal_text(bid), "liquidity": 1000000}],
                            "asks": [{"price": decimal_text(ask), "liquidity": 1000000}],
                        }
                        for sym, (bid, ask) in sorted(quotes.items())
                    ],
                }).encode("utf-8")
            return b'{"errorMessage":"not found"}'

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spool_root = root / "spool"
            emu_hugo = SimMt5SpoolEa(
                spool_root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=1002903,
                quotes=quotes,
                balance=D("0.00"),
                connected=False,
                clock=lambda: T0,
            )
            emu_lhfx = SimMt5SpoolEa(
                spool_root / "lhfx_mt5",
                server="LHFXSA-Trade",
                login=122590,
                quotes=quotes,
                balance=D("97478.59"),
                connected=True,
                clock=lambda: T0,
            )
            emu_hugo.publish_market()
            emu_lhfx.publish_market()

            journal = Mt5MutationJournal(root / "mt5_mutations.sqlite3")
            hugo_venue = Mt5PaperBrokerVenue(
                broker_id=BROKER_HUGOSWAY_MT5,
                credentials=Mt5Credentials(BROKER_HUGOSWAY_MT5, 1002903, "Hugosway-Demo"),
                transport=Mt5SpoolBridgeTransport(spool_root / "hugosway_mt5", sleep=emu_hugo.sleep_hook, clock=lambda: T0),
                valve_gate=gate,
                clock=lambda: T0,
                mutation_journal=journal,
            )
            lhfx_venue = Mt5PaperBrokerVenue(
                broker_id=BROKER_LHFX_MT5,
                credentials=Mt5Credentials(BROKER_LHFX_MT5, 122590, "LHFXSA-Trade"),
                transport=Mt5SpoolBridgeTransport(spool_root / "lhfx_mt5", sleep=emu_lhfx.sleep_hook, clock=lambda: T0),
                valve_gate=gate,
                clock=lambda: T0,
                mutation_journal=journal,
            )
            hugo_venue.connect()
            lhfx_venue.connect()

            oanda_env = {
                "CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID": "101-001-7777777-001",
                "CAS_FOREX_OANDA_PRACTICE_TOKEN": _test_label("oanda"),
                "CAS_FOREX_OANDA_ACCOUNT_ID": "101-001-7777777-001",
                "CAS_FOREX_OANDA_API_TOKEN": _test_label("oanda"),
            }
            oanda_venue = OandaPracticeFallbackVenue(
                client=OandaPracticePaperClient(environ=oanda_env, transport=_fake_oanda_http, clock=lambda: T0),
                valve_gate=gate,
                clock=lambda: T0,
            )
            oanda_venue.connect()

            router = DualShieldBrokerRouter(
                environ={
                    **oanda_env,
                    "CAS_FOREX_HUGOSWAY_MT5_LOGIN": "1002903",
                    "CAS_FOREX_HUGOSWAY_MT5_PASSWORD": _test_label("hugo"),
                    "CAS_FOREX_HUGOSWAY_MT5_SERVER": "Hugosway-Demo",
                    "CAS_FOREX_LHFX_MT5_LOGIN": "122590",
                    "CAS_FOREX_LHFX_MT5_PASSWORD": _test_label("lhfx"),
                    "CAS_FOREX_LHFX_MT5_SERVER": "LHFXSA-Trade",
                    "CAS_FOREX_MT5_SPOOL_DIR": str(spool_root),
                    "CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE": "0",
                },
                valve_gate=gate,
                oracle=OandaQuoteTruthOracle.from_static_quotes(quotes, reference_name="OANDA_PRACTICE_ORACLE"),
                barbell=BarbellCapitalPolicy(demo_virtual_sleeve=False),
                peak_equity_store=PeakEquityStore(root / "peak.sqlite3"),
                mt5_mutation_journal=journal,
                clock=lambda: T0,
            )
            router.attach_venue(hugo_venue)
            router.attach_venue(lhfx_venue)
            router.attach_venue(oanda_venue)

            with (
                mock.patch.object(router, "_sync_mt5_venues_nonblocking", wraps=router._sync_mt5_venues_nonblocking) as sync_spy,
                mock.patch.object(router, "equities", wraps=router.equities) as eq_spy,
            ):
                snap = router.routing_snapshot()

            self.assertEqual(sync_spy.call_count, 1)
            self.assertEqual(eq_spy.call_count, 1)
            alloc = snap["dual_shield"]["allocation"]
            self.assertEqual(alloc["offline_brokers"], [BROKER_HUGOSWAY_MT5])
            self.assertTrue(alloc["equity_incomplete"])
            self.assertEqual(alloc["online_equity"], "197478.59")
            self.assertEqual(alloc["total_equity"], "197478.59")
            self.assertFalse(snap["live_readiness"]["all_gates_ready"])
