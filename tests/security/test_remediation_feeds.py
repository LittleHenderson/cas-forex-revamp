"""Security remediation regression tests for Findings [5] and [6] (public FX feed pinning & fail-closed references)."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

from cas_forex_revamp.contracts import ContractError, Money, RunScope
from cas_forex_revamp.venue import VenueScenario
import cas_forex_revamp.venue.external_paper_broker as broker_mod
from cas_forex_revamp.venue.external_paper_broker import (
    ECB_DAILY_XML_URL,
    EXPANDED_FX_PAIRS,
    FRANKFURTER_ECB_URLS,
    KRAKEN_PUBLIC_TICKER_URL,
    LiveBrokerEndpointForbiddenError,
    LiveFeedVerificationError,
    LiveFxFeedSnapshot,
    NoRedirectHandler,
    PAIR_MAX_REFERENCE_DEVIATION_BPS,
    PAIR_MAX_SPREAD_BPS,
    PublicLiveFxFeedClient,
    SealedLiveFeedPaperVenue,
    _default_https_get,
    build_digest_market_stream_envelope,
    build_market_stream_envelope,
    default_spot_fx_instrument,
    validate_market_stream_for_venue,
    validate_pinned_public_feed_url,
    verify_public_ip_address,
)
import cas_forex_revamp.venue.live_market_stream as stream_mod
from cas_forex_revamp.venue.live_market_stream import (
    DIRECT_KRAKEN_FX_PAIRS,
    EXPANDED_PAIR_SPECS,
    ExpandedPublicLiveFxFeedClient,
    FRANKFURTER_G10_URLS,
    LiveCandleAggregator,
    MarketStreamEnvelope,
    PairMarketStream,
    _https_get_pinned_host,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
INITIAL_STREAM_PATH = REPO_ROOT / "docs" / "contracts" / "initial-market-stream.json"

SAMPLE_ECB_G10_JSON = (
    b'{"amount":1.0,"base":"EUR","date":"2026-11-13",'
    b'"rates":{"AUD":1.6288,"CAD":1.5758,"CHF":0.9266,"GBP":0.83559,"JPY":176.83,"NZD":1.9978,"USD":1.1052}}'
)
SAMPLE_ECB_G10_XML = (
    b"<?xml version='1.0' encoding='UTF-8'?>"
    b"<gesmes:Envelope xmlns:gesmes='http://www.gesmes.org/xml/2002-08-01' "
    b"xmlns='http://www.ecb.int/vocabulary/2002-08-01/eurofxref'>"
    b"<Cube><Cube time='2026-11-13'>"
    b"<Cube currency='USD' rate='1.1052'/>"
    b"<Cube currency='GBP' rate='0.83559'/>"
    b"<Cube currency='JPY' rate='176.83'/>"
    b"<Cube currency='CHF' rate='0.9266'/>"
    b"<Cube currency='AUD' rate='1.6288'/>"
    b"<Cube currency='CAD' rate='1.5758'/>"
    b"<Cube currency='NZD' rate='1.9978'/>"
    b"</Cube></Cube></gesmes:Envelope>"
)
SAMPLE_P5_KRAKEN_BYTES = (
    b'{"error":[],"result":{'
    b'"ZEURZUSD":{"a":["1.10530","10","10.000"],"b":["1.10510","10","10.000"]},'
    b'"ZGBPZUSD":{"a":["1.32280","10","10.000"],"b":["1.32250","10","10.000"]},'
    b'"ZUSDZJPY":{"a":["160.050","10","10.000"],"b":["159.950","10","10.000"]}}}'
)


def _make_expanded_mock_transport(
    *,
    ecb_date: str = "2026-11-13",
    fail_all_refs: bool = False,
    fail_first_ref: bool = False,
    use_xml_ref: bool = False,
    pair_mid_overrides: dict[str, Decimal] | None = None,
    pair_spread_bps_overrides: dict[str, Decimal] | None = None,
    inverted_pair: str | None = None,
):
    _, base_refs = stream_mod.parse_ecb_g10_reference(SAMPLE_ECB_G10_JSON)
    mid_overrides = pair_mid_overrides or {}
    spread_overrides = pair_spread_bps_overrides or {}

    def _http_get(url: str, timeout: float, max_bytes: int) -> bytes:
        if "frankfurter" in url or "ecb.europa.eu" in url:
            if fail_all_refs:
                raise ContractError(f"simulated reference outage at {url}")
            if fail_first_ref and "frankfurter.dev" in url:
                raise ContractError("simulated primary Frankfurter outage")
            if use_xml_ref:
                return SAMPLE_ECB_G10_XML.replace(b"2026-11-13", ecb_date.encode("ascii"))
            doc = json.loads(SAMPLE_ECB_G10_JSON.decode("utf-8"))
            doc["date"] = ecb_date
            return json.dumps(doc).encode("utf-8")

        if "/0/public/Ticker" in url:
            result: dict[str, dict[str, object]] = {}
            for dpair in DIRECT_KRAKEN_FX_PAIRS:
                spec = EXPANDED_PAIR_SPECS[dpair]
                tick = spec["tick"]
                mid = mid_overrides.get(dpair, base_refs[dpair])
                target_spread_bps = spread_overrides.get(dpair, Decimal("4.0"))
                half = (mid * target_spread_bps) / Decimal("20000")
                bid = (mid - half).quantize(tick)
                ask = (mid + half).quantize(tick)
                if ask <= bid:
                    ask = bid + tick
                if inverted_pair == dpair:
                    bid, ask = ask + tick, bid
                key = spec["kraken_keys"][0]
                result[key] = {"b": [str(bid), "100", "100.0"], "a": [str(ask), "100", "100.0"]}
            return json.dumps({"error": [], "result": result}).encode("utf-8")

        if "/0/public/OHLC" in url:
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            pair = q["pair"][0]
            interval = int(q["interval"][0])
            spec = EXPANDED_PAIR_SPECS[pair]
            tick = spec["tick"]
            mid = mid_overrides.get(pair, base_refs[pair]).quantize(tick)
            base_ts = int(datetime(2026, 11, 15, 10, 0, tzinfo=timezone.utc).timestamp())
            rows = []
            for idx in range(6):
                ts = base_ts + idx * interval * 60
                rows.append([
                    ts,
                    str(mid),
                    str(mid + tick * 2),
                    str(mid - tick * 2),
                    str(mid),
                    str(mid),
                    "125.50",
                    12,
                ])
            return json.dumps({"error": [], "result": {pair: rows, "last": rows[-1][0]}}).encode("utf-8")

        if "query1.finance.yahoo.com" in url:
            tick = EXPANDED_PAIR_SPECS["NZDUSD"]["tick"]
            spot = mid_overrides.get("NZDUSD", base_refs["NZDUSD"]).quantize(tick)
            base_ts = int(datetime(2026, 11, 15, 10, 0, tzinfo=timezone.utc).timestamp())
            ts_list = [base_ts + idx * 300 for idx in range(6)]
            px = float(spot)
            payload = {
                "chart": {
                    "result": [
                        {
                            "meta": {"regularMarketPrice": str(spot)},
                            "timestamp": ts_list,
                            "indicators": {
                                "quote": [
                                    {
                                        "open": [px] * 6,
                                        "high": [px + 0.0002] * 6,
                                        "low": [px - 0.0002] * 6,
                                        "close": [px] * 6,
                                        "volume": [100] * 6,
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
            return json.dumps(payload).encode("utf-8")

        raise AssertionError(f"unexpected URL in mock transport: {url}")

    return _http_get


class _FakeRedirectHTTPResponse(io.BytesIO):
    def __init__(self, status: int, headers: dict[str, str]) -> None:
        super().__init__(b"redirect-body")
        self.status = status
        self.code = status
        self.msg = "Redirect"
        self.headers = headers

    def info(self) -> dict[str, str]:
        return self.headers


class PublicFeedPinningAndNoRedirectTests(unittest.TestCase):
    """Finding [5]: Exact HTTPS/443/no-userinfo/no-IP-literal/host+path allowlist and 3xx refusal."""

    T0 = datetime(2026, 11, 15, 11, 0, 0, tzinfo=timezone.utc)

    def test_default_urls_and_all_five_pinned_hosts_validate(self) -> None:
        self.assertFalse(hasattr(broker_mod, "_validate_https_public_url"))
        client = PublicLiveFxFeedClient(
            transport=lambda u, t, m: SAMPLE_P5_KRAKEN_BYTES if "kraken" in u else SAMPLE_ECB_G10_JSON
        )
        snap = client.fetch_live_quotes(now=self.T0)
        self.assertTrue(snap.verify_integrity())

        allowed_urls = (
            KRAKEN_PUBLIC_TICKER_URL,
            "https://api.kraken.com:443/0/public/Ticker?pair=EURUSD",
            "https://api.kraken.com/0/public/OHLC?pair=EURUSD&interval=5",
            ECB_DAILY_XML_URL,
            "https://www.ecb.europa.eu:443/stats/eurofxref/eurofxref-daily.xml",
            "https://data-api.ecb.europa.eu/service/data/EXR",
            "https://data-api.ecb.europa.eu/service/data/EXR/D.USD+GBP+JPY.EUR.SP00.A?lastNObservations=1",
            FRANKFURTER_ECB_URLS[0],
            FRANKFURTER_ECB_URLS[1],
        )
        for url in allowed_urls:
            with self.subTest(url=url):
                self.assertEqual(validate_pinned_public_feed_url(url), url)

        data_api_client = PublicLiveFxFeedClient(
            ecb_reference_urls=("https://data-api.ecb.europa.eu/service/data/EXR/D.USD+GBP+JPY.EUR.SP00.A",),
            transport=lambda u, t, m: SAMPLE_P5_KRAKEN_BYTES if "kraken" in u else SAMPLE_ECB_G10_XML,
        )
        snap2 = data_api_client.fetch_live_quotes(now=self.T0)
        self.assertTrue(snap2.verify_integrity())

    def test_rejects_unpinned_hosts_schemes_ports_userinfo_fragments_and_paths(self) -> None:
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            PublicLiveFxFeedClient(kraken_ticker_url="https://api-fxtrade.oanda.com/v3/pricing")
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            PublicLiveFxFeedClient(ecb_reference_urls=("https://stream-fxtrade.oanda.com/v3/pricing",))

        rejected_urls = (
            "",
            "http://api.kraken.com/0/public/Ticker",
            "ftp://api.kraken.com/0/public/Ticker",
            "https://evil.example.com/0/public/Ticker",
            "https://api.kraken.com.evil.com/0/public/Ticker",
            "https://evil-api.kraken.com/0/public/Ticker",
            "https://api.kraken.com./0/public/Ticker",
            "https://API.KRAKEN.COM/0/public/Ticker",
            "https://api.kraken.com\\@evil.com/0/public/Ticker",
            "https://user:pass@api.kraken.com/0/public/Ticker",
            "https://@api.kraken.com/0/public/Ticker",
            "https://api.kraken.com@evil.com/0/public/Ticker",
            "https://api.kraken.com:8443/0/public/Ticker",
            "https://api.kraken.com:80/0/public/Ticker",
            "https://api.kraken.com:/0/public/Ticker",
            "https://api.kraken.com:0443/0/public/Ticker",
            "https://api.kraken.com/0/public/Ticker#frag",
            "https://api.kraken.com/0/public/Ticker#",
            "https://api.kraken.com/0/private/Balance",
            "https://api.kraken.com/0/public/Ticker/../private/Balance",
            "https://api.kraken.com/0/public/Ticker%2f..%2fprivate",
            "https://api.kraken.com//0/public/Ticker",
            "https://www.ecb.europa.eu/stats/other.xml",
            "https://data-api.ecb.europa.eu/service/data/BSI",
            "https://data-api.ecb.europa.eu/service/data/EXR/../../admin",
            "https://api.frankfurter.app/v1/latest",
            "https://api.frankfurter.dev/latest",
            "https://query1.finance.yahoo.com/v8/finance/chart/NZDUSD=X",
        )
        for bad in rejected_urls:
            with self.subTest(bad=bad), self.assertRaises(ContractError):
                validate_pinned_public_feed_url(bad)

        # Role confusion between Kraken ticker URL and ECB reference URL is also rejected
        with self.assertRaises(ContractError):
            PublicLiveFxFeedClient(kraken_ticker_url=ECB_DAILY_XML_URL)
        with self.assertRaises(ContractError):
            PublicLiveFxFeedClient(ecb_reference_urls=(KRAKEN_PUBLIC_TICKER_URL,))

    def test_rejects_private_loopback_link_local_ip_literals_and_dns_rebinding(self) -> None:
        ip_urls = (
            "https://127.0.0.1/0/public/Ticker",
            "https://[::1]/0/public/Ticker",
            "https://[::ffff:127.0.0.1]/0/public/Ticker",
            "https://10.0.0.1/0/public/Ticker",
            "https://172.16.5.4/0/public/Ticker",
            "https://192.168.1.10/0/public/Ticker",
            "https://169.254.169.254/latest",
            "https://[fe80::1]/latest",
            "https://[fc00::1]/latest",
            "https://2130706433/0/public/Ticker",
            "https://0x7f000001/0/public/Ticker",
            "https://1.1.1.1/0/public/Ticker",
        )
        for bad in ip_urls:
            with self.subTest(bad=bad), self.assertRaises(ContractError):
                validate_pinned_public_feed_url(bad)
            with self.subTest(client_bad=bad), self.assertRaises(ContractError):
                PublicLiveFxFeedClient(kraken_ticker_url=bad)

        for non_public_ip in (
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "10.1.2.3",
            "172.20.0.1",
            "192.168.0.1",
            "169.254.169.254",
            "::ffff:169.254.169.254",
            "100.64.0.1",
            "fe80::1",
            "fe80::1%eth0",
            "fc00::1234",
            "0.0.0.0",
            "224.0.0.1",
        ):
            with self.subTest(resolved_ip=non_public_ip), self.assertRaises(ContractError):
                verify_public_ip_address(non_public_ip)

        # Verify DNS resolution to private/loopback/link-local is blocked before socket.socket()
        for rebind_ip in ("127.0.0.1", "169.254.169.254", "10.0.0.8"):
            fake_addrinfo = [(2, 1, 6, "", (rebind_ip, 443))]
            with self.subTest(dns_rebind=rebind_ip), \
                 patch("socket.getaddrinfo", return_value=fake_addrinfo), \
                 patch("socket.socket", side_effect=AssertionError("socket must never open on private IP")):
                with self.assertRaises(LiveFeedVerificationError):
                    _default_https_get(KRAKEN_PUBLIC_TICKER_URL, 5.0, 4096)
                with self.assertRaises(ContractError):
                    _https_get_pinned_host(KRAKEN_PUBLIC_TICKER_URL, timeout_seconds=5.0, max_bytes=4096, retries=0)

    def test_no_redirect_handler_rejects_every_3xx_without_following_hop(self) -> None:
        for code in (300, 301, 302, 303, 304, 305, 307, 308):
            for headers in (
                {"Location": "https://evil.example.com/ssrf"},
                {"Location": KRAKEN_PUBLIC_TICKER_URL},
                {},
            ):
                calls: list[str] = []

                def _fake_https_open(_self, req):
                    calls.append(req.full_url)
                    return _FakeRedirectHTTPResponse(code, headers)

                with self.subTest(code=code, has_location=bool(headers)), \
                     patch.object(stream_mod.PinnedPublicHTTPSHandler, "https_open", _fake_https_open):
                    with self.assertRaises(LiveFeedVerificationError):
                        _default_https_get(KRAKEN_PUBLIC_TICKER_URL, 5.0, 4096)
                    self.assertEqual(calls, [KRAKEN_PUBLIC_TICKER_URL])

                    calls.clear()
                    with self.assertRaises(ContractError):
                        _https_get_pinned_host(
                            KRAKEN_PUBLIC_TICKER_URL,
                            timeout_seconds=5.0,
                            max_bytes=4096,
                            retries=2,
                        )
                    self.assertEqual(calls, [KRAKEN_PUBLIC_TICKER_URL])

        handler = NoRedirectHandler()
        with self.assertRaises(LiveFeedVerificationError):
            handler.redirect_request(None, None, 302, "Found", {}, "https://api.kraken.com/0/public/Ticker")


class ExpandedFeedFailClosedAndVenueIntegrityTests(unittest.TestCase):
    """Finding [6]: Fail-closed references, freshness/deviation/spread gates, venue non-mutation, digest naming."""

    T0 = datetime(2026, 11, 15, 11, 27, 42, tzinfo=timezone.utc)

    def test_expanded_client_fails_closed_when_all_reference_feeds_fail(self) -> None:
        client = ExpandedPublicLiveFxFeedClient(
            http_get=_make_expanded_mock_transport(fail_all_refs=True),
        )
        with self.assertRaises(ContractError):
            client.fetch_market_stream(now=self.T0)

    def test_expanded_client_succeeds_via_secondary_or_xml_reference_and_validates(self) -> None:
        client_fallback = ExpandedPublicLiveFxFeedClient(
            http_get=_make_expanded_mock_transport(fail_first_ref=True),
        )
        env = client_fallback.fetch_market_stream(now=self.T0)
        self.assertEqual(env.ecb_reference_date, "2026-11-13")
        self.assertEqual(len(env.streams), 16)
        validate_market_stream_for_venue(env, now=self.T0)

        client_xml = ExpandedPublicLiveFxFeedClient(
            reference_urls=(ECB_DAILY_XML_URL,),
            http_get=_make_expanded_mock_transport(use_xml_ref=True),
        )
        env_xml = client_xml.fetch_market_stream(now=self.T0)
        self.assertEqual(env_xml.ecb_reference_date, "2026-11-13")
        validate_market_stream_for_venue(env_xml, now=self.T0)

    def test_stale_or_future_reference_date_rejected_fail_closed(self) -> None:
        stale_client = ExpandedPublicLiveFxFeedClient(
            http_get=_make_expanded_mock_transport(ecb_date="2026-11-08"),
            max_reference_age_days=5,
        )
        with self.assertRaises(ContractError):
            stale_client.fetch_market_stream(now=self.T0)

        strict_age_client = ExpandedPublicLiveFxFeedClient(
            http_get=_make_expanded_mock_transport(ecb_date="2026-11-13"),
            max_reference_age_days=1,
        )
        with self.assertRaises(ContractError):
            strict_age_client.fetch_market_stream(now=self.T0)

        future_client = ExpandedPublicLiveFxFeedClient(
            http_get=_make_expanded_mock_transport(ecb_date="2026-11-18"),
        )
        with self.assertRaises(ContractError):
            future_client.fetch_market_stream(now=self.T0)

        # Phase 5 PublicLiveFxFeedClient also enforces max_reference_age_days
        p5_stale = PublicLiveFxFeedClient(
            max_reference_age_days=1,
            transport=lambda u, t, m: SAMPLE_P5_KRAKEN_BYTES if "kraken" in u else SAMPLE_ECB_G10_JSON,
        )
        with self.assertRaises(LiveFeedVerificationError):
            p5_stale.fetch_live_quotes(now=self.T0)

    def test_pair_specific_reference_deviation_and_spread_limits_enforced(self) -> None:
        _, refs = stream_mod.parse_ecb_g10_reference(SAMPLE_ECB_G10_JSON)

        # EURUSD pair max_reference_deviation_bps is 250 bps; +280 bps must fail closed
        eur_280bps = (refs["EURUSD"] * Decimal("1.0280")).quantize(Decimal("0.00001"))
        c_eur_dev = ExpandedPublicLiveFxFeedClient(
            http_get=_make_expanded_mock_transport(pair_mid_overrides={"EURUSD": eur_280bps}),
        )
        with self.assertRaises(ContractError):
            c_eur_dev.fetch_market_stream(now=self.T0)

        # EURJPY cross pair max_reference_deviation_bps is 350 bps: +310 bps passes, +370 bps fails
        eurjpy_310bps = (refs["EURJPY"] * Decimal("1.0310")).quantize(Decimal("0.001"))
        c_cross_ok = ExpandedPublicLiveFxFeedClient(
            http_get=_make_expanded_mock_transport(pair_mid_overrides={"EURJPY": eurjpy_310bps}),
        )
        env_ok = c_cross_ok.fetch_market_stream(now=self.T0)
        self.assertEqual(len(env_ok.streams), 16)

        eurjpy_370bps = (refs["EURJPY"] * Decimal("1.0370")).quantize(Decimal("0.001"))
        c_cross_bad = ExpandedPublicLiveFxFeedClient(
            http_get=_make_expanded_mock_transport(pair_mid_overrides={"EURJPY": eurjpy_370bps}),
        )
        with self.assertRaises(ContractError):
            c_cross_bad.fetch_market_stream(now=self.T0)

        # EURUSD pair max_spread_bps is 100 bps; 130 bps fails, while USDJPY at 220 bps (<= 300 bps) passes
        c_eur_spread_bad = ExpandedPublicLiveFxFeedClient(
            http_get=_make_expanded_mock_transport(pair_spread_bps_overrides={"EURUSD": Decimal("130")}),
        )
        with self.assertRaises(ContractError):
            c_eur_spread_bad.fetch_market_stream(now=self.T0)

        c_jpy_spread_ok = ExpandedPublicLiveFxFeedClient(
            http_get=_make_expanded_mock_transport(pair_spread_bps_overrides={"USDJPY": Decimal("220")}),
        )
        self.assertEqual(len(c_jpy_spread_ok.fetch_market_stream(now=self.T0).streams), 16)

        # Inverted primary Kraken quote fails closed instead of fabricating ask = bid + tick
        c_inverted = ExpandedPublicLiveFxFeedClient(
            http_get=_make_expanded_mock_transport(inverted_pair="EURUSD"),
        )
        with self.assertRaises(ContractError):
            c_inverted.fetch_market_stream(now=self.T0)

    def test_venue_ingest_market_stream_leaves_sequence_and_audit_unchanged_on_rejection(self) -> None:
        base_env = MarketStreamEnvelope.from_json_bytes(INITIAL_STREAM_PATH.read_bytes())
        obs_now = base_env.observed_at + timedelta(seconds=5)
        scope = RunScope("acct-sec6", "run-sec6", 1, "build-sec6", "pol-sec6", "scen-sec6", "venue-sec6")
        instruments = tuple(default_spot_fx_instrument(sym) for sym in ("AUDUSD", "EURUSD", "GBPUSD", "NZDUSD"))

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            venue_path = Path(tmp) / "sec6.venue.sqlite3"
            venue = SealedLiveFeedPaperVenue(venue_path)
            init_snap = venue.initialize(
                scope.key,
                opening_balance=Money(Decimal("10000.00"), "USD"),
                instruments=instruments,
                now=base_env.observed_at,
                scenario=VenueScenario(scope.scenario_id),
            )
            good_snap = venue.ingest_market_stream(base_env, key=scope.key, now=obs_now)
            self.assertEqual(good_snap.sequence, init_snap.sequence + len(instruments))

            before_seq = venue.snapshot(scope.key, now=obs_now).sequence
            before_venue_journal = venue.inspect_journal(scope.key)
            before_audit_journal = venue.inspect_audit_journal(scope.key)
            before_retained = venue.read_market_stream()

            def _rebuild(
                *,
                ecb_date: str | None = base_env.ecb_reference_date,
                mutate_pair: str | None = None,
                mutator=None,
            ) -> MarketStreamEnvelope:
                updated: list[PairMarketStream] = []
                for ps in base_env.streams:
                    if ps.pair == mutate_pair and mutator is not None:
                        updated.append(mutator(ps))
                    else:
                        updated.append(ps)
                return build_market_stream_envelope(
                    stream_id="fxstream-bad",
                    sequence=base_env.sequence + 1,
                    observed_at=obs_now,
                    observed_at_ns=base_env.observed_at_ns,
                    source_mode=base_env.source_mode,
                    raw_wire_sha256=base_env.raw_wire_sha256,
                    ecb_reference_date=ecb_date,
                    valve_status=base_env.valve_status,
                    streams=updated,
                )

            # 1. Missing ecb_reference_date
            env_no_date = _rebuild(ecb_date=None)

            # 2. Stale ecb_reference_date (> 5 days)
            env_stale = _rebuild(ecb_date="2026-10-15")

            # 3. Missing pair ecb_reference_mid on GBPUSD (3rd sorted symbol -> tests atomicity after AUDUSD/EURUSD)
            env_no_ref_mid = _rebuild(
                mutate_pair="GBPUSD",
                mutator=lambda ps: replace(ps, ecb_reference_mid=None, ecb_deviation_bps=None),
            )

            # 4. GBPUSD deviation > 250 bps (with honest ecb_deviation_bps)
            def _make_divergent_gbp(ps: PairMarketStream) -> PairMarketStream:
                self.assertIsNotNone(ps.ecb_reference_mid)
                ref_mid = ps.ecb_reference_mid if ps.ecb_reference_mid is not None else Decimal("1")
                bad_mid = (ref_mid * Decimal("1.0300")).quantize(ps.tick_size)
                bad_bid = bad_mid - ps.tick_size * 4
                bad_ask = bad_mid + ps.tick_size * 4
                dev = ((abs(bad_mid - ref_mid) / ref_mid) * Decimal("10000")).quantize(
                    Decimal("0.1")
                )
                return replace(
                    ps,
                    bid=bad_bid,
                    ask=bad_ask,
                    mid=bad_mid,
                    spread_pips=Decimal("0.8"),
                    ecb_deviation_bps=dev,
                )

            env_divergent = _rebuild(mutate_pair="GBPUSD", mutator=_make_divergent_gbp)

            # 5. Spoofed low ecb_deviation_bps="1.0" masking a 300 bps divergent quote
            env_spoofed_dev = _rebuild(
                mutate_pair="GBPUSD",
                mutator=lambda ps: replace(_make_divergent_gbp(ps), ecb_deviation_bps=Decimal("1.0")),
            )

            # 6. NZDUSD (4th sorted symbol) wide spread > 100 bps
            def _make_wide_nzd(ps: PairMarketStream) -> PairMarketStream:
                wide_bid = (ps.mid - Decimal("0.00400")).quantize(ps.tick_size)
                wide_ask = (ps.mid + Decimal("0.00400")).quantize(ps.tick_size)
                return replace(ps, bid=wide_bid, ask=wide_ask, spread_pips=Decimal("80.0"))

            env_wide_spread = _rebuild(mutate_pair="NZDUSD", mutator=_make_wide_nzd)

            for label, bad_env in (
                ("missing_ref_date", env_no_date),
                ("stale_ref_date", env_stale),
                ("missing_pair_ref_mid", env_no_ref_mid),
                ("divergent_gbpusd", env_divergent),
                ("spoofed_dev_bps", env_spoofed_dev),
                ("wide_spread_nzdusd", env_wide_spread),
            ):
                with self.subTest(case=label):
                    with self.assertRaises(ContractError):
                        venue.ingest_market_stream(bad_env, key=scope.key, now=obs_now + timedelta(seconds=1))
                    self.assertEqual(venue.snapshot(scope.key, now=obs_now).sequence, before_seq)
                    self.assertEqual(venue.inspect_journal(scope.key), before_venue_journal)
                    self.assertEqual(venue.inspect_audit_journal(scope.key), before_audit_journal)
                    self.assertEqual(venue.read_market_stream(), before_retained)

    def test_live_candle_aggregator_rejects_bad_ticks_without_advancing_sequence(self) -> None:
        env0 = MarketStreamEnvelope.from_json_bytes(INITIAL_STREAM_PATH.read_bytes())
        agg = LiveCandleAggregator(env0)
        t_next = env0.observed_at + timedelta(seconds=15)

        # Divergent EURUSD quote (> 250 bps) rejected without advancing sequence
        with self.assertRaises(ContractError):
            agg.ingest_quotes({"EURUSD": (Decimal("1.15000"), Decimal("1.15010"))}, observed_at=t_next)

        # Wide EURUSD spread (> 100 bps) rejected without advancing sequence
        with self.assertRaises(ContractError):
            agg.ingest_quotes({"EURUSD": (Decimal("1.09500"), Decimal("1.11500"))}, observed_at=t_next)

        # Valid quote still advances cleanly from original sequence (proving failed calls did not mutate _sequence)
        env1 = agg.ingest_quotes({"EURUSD": (Decimal("1.09900"), Decimal("1.09910"))}, observed_at=t_next)
        self.assertEqual(env1.sequence, env0.sequence + 1)

    def test_self_computed_sha256_digests_are_not_labeled_signatures_and_fixture_unchanged(self) -> None:
        raw_fixture = INITIAL_STREAM_PATH.read_bytes()
        env = MarketStreamEnvelope.from_json_bytes(raw_fixture)
        validate_market_stream_for_venue(env)
        self.assertEqual(len(env.streams), len(EXPANDED_FX_PAIRS))
        self.assertEqual(set(PAIR_MAX_REFERENCE_DEVIATION_BPS), set(EXPANDED_FX_PAIRS))
        self.assertEqual(set(PAIR_MAX_SPREAD_BPS), set(EXPANDED_FX_PAIRS))

        self.assertIs(build_digest_market_stream_envelope, build_market_stream_envelope)
        self.assertFalse(hasattr(stream_mod, "build_signed_market_stream_envelope"))
        self.assertFalse(hasattr(broker_mod, "build_signed_market_stream_envelope"))
        self.assertFalse(hasattr(MarketStreamEnvelope, "_unsigned_dict"))
        self.assertFalse(hasattr(LiveFxFeedSnapshot, "_unsigned_body_dict"))
        self.assertTrue(hasattr(MarketStreamEnvelope, "_payload_without_digest_dict"))
        self.assertTrue(hasattr(MarketStreamEnvelope, "verify_digest"))
        self.assertTrue(hasattr(LiveFxFeedSnapshot, "_body_without_digest_dict"))

        wire_keys = set(env.to_wire_dict().keys())
        self.assertIn("raw_wire_sha256", wire_keys)
        self.assertIn("canonical_payload_sha256", wire_keys)
        for key in wire_keys:
            self.assertNotIn("sign", key.lower())
        self.assertEqual(sha256(raw_fixture).hexdigest(), sha256(INITIAL_STREAM_PATH.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
