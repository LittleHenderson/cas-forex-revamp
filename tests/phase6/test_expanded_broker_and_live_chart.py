"""Phase 6 unit & integration suite for 16-pair FX stream, candle aggregation, and loopback UI bridge."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
import urllib.request

from cas_forex_revamp.composition.application import RuntimeConfig
from cas_forex_revamp.composition.evidence_journal import EvidenceJournal
from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer, validate_loopback_host
from cas_forex_revamp.composition.owner_requests import OwnerRequestBook
from cas_forex_revamp.composition.read_service import DecisionReadService
from cas_forex_revamp.composition.ui_service import ScopedUIService
from cas_forex_revamp.contracts import ControlKind, DecisionOrigin, Money, RunScope
from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.core import InstrumentPolicy, RiskPolicy
from cas_forex_revamp.venue import VenueScenario
from cas_forex_revamp.venue.external_paper_broker import (
    DIRECT_KRAKEN_FX_PAIRS,
    EXPANDED_FX_PAIRS,
    ExpandedPublicLiveFxFeedClient,
    LiveCandleAggregator,
    MarketStreamEnvelope,
    OhlcCandleBar,
    SUPPORTED_FX_PAIRS,
    assemble_live_feed_paper_simulation,
    assert_safe_json_numbers,
    default_spot_fx_instrument,
    parse_ecb_g10_reference,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
INITIAL_STREAM_PATH = REPO_ROOT / "docs" / "contracts" / "initial-market-stream.json"


class _Clock:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        self.now = self.now + timedelta(milliseconds=50)
        return self.now


class _InertAdapter:
    def decide(self, request):
        raise AssertionError("inert adapter")


class ExpandedBrokerAndChartTests(unittest.TestCase):
    def test_phase5_default_pairs_unchanged_and_expanded_has_16_pairs(self) -> None:
        self.assertEqual(SUPPORTED_FX_PAIRS, ("EURUSD", "GBPUSD", "USDJPY"))
        self.assertEqual(len(DIRECT_KRAKEN_FX_PAIRS), 12)
        self.assertEqual(len(EXPANDED_FX_PAIRS), 16)
        for must_have in ("EURUSD", "GBPUSD", "USDJPY", "USDCHF", "AUDUSD", "USDCAD", "NZDUSD", "EURGBP", "EURJPY", "GBPJPY"):
            self.assertIn(must_have, EXPANDED_FX_PAIRS)
            inst = default_spot_fx_instrument(must_have)
            self.assertEqual(inst.symbol, must_have)

    def test_initial_market_stream_envelope_verifies_all_16_pairs_and_safe_json(self) -> None:
        raw = INITIAL_STREAM_PATH.read_bytes()
        env = MarketStreamEnvelope.from_json_bytes(raw)
        self.assertEqual(len(env.streams), 16)
        assert_safe_json_numbers(env.to_wire_dict())
        pmap = env.pair_map()
        for pair in EXPANDED_FX_PAIRS:
            self.assertIn(pair, pmap)
            ps = pmap[pair]
            self.assertGreater(ps.bid, Decimal("0"))
            self.assertGreater(ps.ask, ps.bid)
            self.assertGreaterEqual(len(ps.candles_m1), 1)
            self.assertGreaterEqual(len(ps.candles_m5), 1)
            self.assertGreaterEqual(len(ps.candles_h1), 1)

    def test_tampered_market_stream_digest_rejected(self) -> None:
        doc = json.loads(INITIAL_STREAM_PATH.read_text(encoding="utf-8"))
        doc["streams"][0]["mid"] = doc["streams"][0]["ask"]
        with self.assertRaises(ContractError):
            MarketStreamEnvelope.from_json_bytes(json.dumps(doc))

    def test_ohlc_candle_bar_rejects_inverted_high_low(self) -> None:
        t0 = datetime(2026, 11, 15, 10, 0, tzinfo=timezone.utc)
        with self.assertRaises(ContractError):
            OhlcCandleBar(t0, Decimal("1.1000"), Decimal("1.0990"), Decimal("1.0980"), Decimal("1.0995"), Decimal("10"), 1)

    def test_ecb_g10_reference_derives_all_16_pairs(self) -> None:
        sample = b'{"amount":1.0,"base":"EUR","date":"2026-11-13","rates":{"AUD":1.6288,"CAD":1.5758,"CHF":0.9266,"GBP":0.83559,"JPY":176.83,"NZD":1.9978,"USD":1.1052}}'
        ref_date, refs = parse_ecb_g10_reference(sample)
        self.assertEqual(ref_date, "2026-11-13")
        self.assertEqual(set(refs.keys()), set(EXPANDED_FX_PAIRS))
        for val in refs.values():
            self.assertGreater(val, Decimal("0"))

    def test_live_candle_aggregator_updates_forming_bar_and_rolls_new_minute_bar(self) -> None:
        env0 = MarketStreamEnvelope.from_json_bytes(INITIAL_STREAM_PATH.read_bytes())
        agg = LiveCandleAggregator(env0)
        eur0 = env0.pair_map()["EURUSD"]
        last_open = eur0.candles_m1[-1].open_utc
        new_high_bid = eur0.candles_m1[-1].high_price + Decimal("0.00100")
        new_high_ask = new_high_bid + Decimal("0.00010")
        env1 = agg.ingest_quotes(
            {"EURUSD": (new_high_bid, new_high_ask)},
            observed_at=last_open + timedelta(seconds=25),
        )
        self.assertEqual(env1.sequence, env0.sequence + 1)
        self.assertGreaterEqual(env1.pair_map()["EURUSD"].candles_m1[-1].high_price, new_high_bid)

        next_bucket_dt = last_open + timedelta(minutes=2, seconds=5)
        env2 = agg.ingest_quotes(
            {"EURUSD": (new_high_bid, new_high_ask)},
            observed_at=next_bucket_dt,
        )
        self.assertGreater(env2.pair_map()["EURUSD"].candles_m1[-1].open_utc, last_open)

    def test_expanded_client_refuses_unpinned_host_and_http(self) -> None:
        client = ExpandedPublicLiveFxFeedClient()
        with self.assertRaises(ContractError):
            client._get("http://api.kraken.com/0/public/Ticker")
        with self.assertRaises(ContractError):
            client._get("https://evil.example.com/0/public/Ticker")

    def test_sealed_venue_ingests_16pair_stream_and_ui_read_remains_mutation_free(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = MarketStreamEnvelope.from_json_bytes(INITIAL_STREAM_PATH.read_bytes())
            clk = _Clock(env.observed_at)
            scope = RunScope("acct-p6", "run-p6", 1, "build-p6", "pol-p6", "scen-p6", "venue-p6")
            # v1 CoreCoordinator requires quote currency == account currency (USD), so use the 4 USD-quoted pairs.
            instruments = tuple(default_spot_fx_instrument(sym) for sym in ("EURUSD", "GBPUSD", "AUDUSD", "NZDUSD"))
            policies = tuple(InstrumentPolicy(inst, Decimal("50")) for inst in instruments)
            owner = OwnerRequestBook(scope, controls=frozenset(ControlKind), reviewed_close=True)
            sim = assemble_live_feed_paper_simulation(
                RuntimeConfig(scope, root),
                policy=RiskPolicy("USD", Decimal("1000")),
                instruments=policies,
                decision_adapter=_InertAdapter(),
                clock=clk,
                owner_verifier=owner,
                expected_origin=DecisionOrigin.ACTUAL_MODEL,
            )
            journal = EvidenceJournal(root / "phase6.evidence.sqlite3", scope.key)
            journal.initialize(create=True)
            sim.venue.initialize(scope.key, opening_balance=Money(Decimal("10000"), "USD"), instruments=instruments, now=clk(), scenario=VenueScenario(scope.scenario_id))
            sim.core.initialize(create=True)
            snap = sim.venue.ingest_market_stream(env, key=scope.key, now=clk())
            self.assertEqual(len(snap.market), 4)

            schema_bytes = (REPO_ROOT / "docs" / "contracts" / "decision-read.schema.json").read_bytes()
            reader = DecisionReadService(
                scope=scope,
                core=sim.core,
                venue=sim.venue,
                journal=journal,
                clock=clk,
                schema_bytes=schema_bytes,
                schema_sha256=sha256(schema_bytes).hexdigest(),
                instruments=instruments,
            )
            ui = ScopedUIService(app=sim, owner=owner, journal=journal, reader=reader, clock=clk)
            before = (sim.core.read_snapshot(scope.key), sim.venue.inspect_journal(scope.key), journal.records())
            m_wire = ui.readMarketStream()
            after = (sim.core.read_snapshot(scope.key), sim.venue.inspect_journal(scope.key), journal.records())
            self.assertEqual(before, after)
            self.assertIsNotNone(m_wire)
            self.assertEqual(len(m_wire["streams"]), 16)

    def test_loopback_server_refuses_non_loopback_bind(self) -> None:
        self.assertEqual(validate_loopback_host("127.0.0.1"), "127.0.0.1")
        with self.assertRaises(ContractError):
            validate_loopback_host("0.0.0.0")
        with self.assertRaises(ContractError):
            LoopbackCockpitServer(repo_root=REPO_ROOT, host="0.0.0.0")

    def test_loopback_server_serves_csp_static_ui_stream_and_blocks_path_traversal(self) -> None:
        env = MarketStreamEnvelope.from_json_bytes(INITIAL_STREAM_PATH.read_bytes())
        srv = LoopbackCockpitServer(
            repo_root=REPO_ROOT,
            host="127.0.0.1",
            port=0,
            market_stream_reader=env.to_wire_dict,
        )
        base_url = srv.start()
        try:
            with urllib.request.urlopen(base_url + "/ui/index.html", timeout=5) as r_html:
                self.assertEqual(r_html.status, 200)
                self.assertIn("default-src 'none'", r_html.headers.get("Content-Security-Policy", ""))
                body_html = r_html.read().decode("utf-8")
                self.assertIn("CAS Forex", body_html)

            with urllib.request.urlopen(base_url + "/api/market-stream", timeout=5) as r_ms:
                self.assertEqual(r_ms.status, 200)
                doc = json.loads(r_ms.read().decode("utf-8"))
                self.assertEqual(len(doc["streams"]), 16)

            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(base_url + "/../src/cas_forex_revamp/venue/live_market_stream.py", timeout=5)
            self.assertEqual(ctx.exception.code, 404)
            ctx.exception.close()
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()
