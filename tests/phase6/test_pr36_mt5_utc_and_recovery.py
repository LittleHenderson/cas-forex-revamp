"""PR #36 regression tests: MQL5 server-time->UTC tick/candle conversion & SNAPSHOT_UNVERIFIED recovery."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import inspect
import json
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest

from cas_forex_revamp.contracts import ActionKind, Side
from cas_forex_revamp.valve.tks_meta_valve_controller import ValveDecision, load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.external_paper_broker import (
    ENV_OANDA_PRACTICE_ACCOUNT_ID,
    ENV_OANDA_PRACTICE_TOKEN,
    OandaPracticePaperClient,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    ENV_HUGOSWAY_MT5_LOGIN,
    ENV_HUGOSWAY_MT5_PASSWORD,
    ENV_HUGOSWAY_MT5_SERVER,
    ENV_LHFX_MT5_LOGIN,
    ENV_LHFX_MT5_SERVER,
    ENV_MT5_SPOOL_DIR,
    ENV_MT5_TRANSPORT_MODE,
    Mt5Credentials,
    Mt5SnapshotIntegrityError,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    OrderIntent,
    TRANSPORT_SPOOL_BRIDGE,
    sign_mt5_market_snapshot_doc,
)

D = Decimal
T0 = datetime(2026, 11, 22, 23, 55, 0, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[2]
MQ5_PATH = REPO_ROOT / "mt5" / "CasForexMt5Bridge.mq5"


def _test_fixture_val(slot: str) -> str:
    return f"pr36-unit-fixture-{slot}"


class _MutableClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int | float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


class _StubOandaTransport:
    def __init__(self, *, account_id: str = "101-001-3600001-001", equity: str = "100000.00") -> None:
        self.account_id = account_id
        self.equity = equity

    def __call__(self, method: str, url: str, *_args: object) -> bytes:
        if method.upper() == "GET" and url.endswith("/summary"):
            return json.dumps({
                "lastTransactionID": "100",
                "account": {
                    "id": self.account_id,
                    "currency": "USD",
                    "balance": self.equity,
                    "NAV": self.equity,
                    "unrealizedPL": "0.00",
                    "marginAvailable": self.equity,
                    "openPositionCount": 0,
                    "lastTransactionID": "100",
                },
            }).encode("utf-8")
        if method.upper() == "GET" and "/pricing" in url:
            return json.dumps({
                "time": T0.isoformat().replace("+00:00", "Z"),
                "prices": [{
                    "instrument": "EUR_USD",
                    "time": T0.isoformat().replace("+00:00", "Z"),
                    "bids": [{"price": "1.10000", "liquidity": 1000000}],
                    "asks": [{"price": "1.10010", "liquidity": 1000000}],
                    "tradeable": True,
                }],
            }).encode("utf-8")
        return json.dumps({"lastTransactionID": "100", "trades": []}).encode("utf-8")


def _extract_mql5_fn(source: str, signature_prefix: str) -> str:
    idx = source.index(signature_prefix)
    brace_start = source.index("{", idx)
    depth = 0
    for pos in range(brace_start, len(source)):
        ch = source[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[idx : pos + 1]
    raise AssertionError(f"Unclosed MQL5 block for {signature_prefix}")


def _py_server_utc_offset_seconds(srv_now: int, gmt_now: int) -> int:
    if srv_now <= 0 or gmt_now <= 0:
        return 0
    raw_off = srv_now - gmt_now
    if raw_off < -43200 or raw_off > 50400:
        return 0
    if raw_off >= 0:
        return ((raw_off + 450) // 900) * 900
    return -((((-raw_off) + 450) // 900) * 900)


def _admit_open_order(gate, order: OrderIntent, *, now: datetime) -> ValveDecision:
    intent = SimpleNamespace(
        intent_id=order.order_id,
        action_ref=order.action_ref,
        kind=order.kind,
        instrument_id=order.symbol,
        quantity=order.quantity_units,
        side=order.side,
        stop_price=order.stop_price,
        limit_price=order.limit_price,
        take_profit_price=order.take_profit_price,
        target_id=order.position_ticket,
    )
    req = SimpleNamespace(
        request_id=f"req-{order.order_id}",
        facts=(),
        evidence=(SimpleNamespace(evidence_id="ev-1"),),
        state=SimpleNamespace(observed_at=now, valid_until=now + timedelta(minutes=5)),
    )
    sel = SimpleNamespace(evidence_ids=("ev-1",), reason="pr36 test", selected_action_ref=order.action_ref)
    prop = SimpleNamespace(request=req, result=SimpleNamespace(selection=sel), intent=intent)
    view = {"balance": "100000", "equity": "100000", "available_margin": "90000", "position_inventory": "[]"}
    pol = {"new_risk_permission": "ALLOWED", "management_permission": "ALLOWED", "max_entry_quantity": "10000000"}
    return gate.require_admissible(prop, current_view=view, policy=pol, now=now)


class Pr36Mt5UtcAndRecoveryTests(unittest.TestCase):
    def test_mql5_server_utc_offset_parity_and_safety(self) -> None:
        mq5 = MQ5_PATH.read_text(encoding="utf-8")
        offset_fn = _extract_mql5_fn(mq5, "long ServerUtcOffsetSeconds()")
        candles_fn = _extract_mql5_fn(mq5, "string CandleSeriesJson(")
        pub_fn = _extract_mql5_fn(mq5, "void PublishMarket()")

        # 1. Uses TimeTradeServer() - TimeGMT(), never TimeCurrent()
        self.assertIn("TimeTradeServer()", offset_fn)
        self.assertIn("TimeGMT()", offset_fn)
        self.assertNotIn("TimeCurrent()", offset_fn)
        self.assertIn("-43200", offset_fn)
        self.assertIn("50400", offset_fn)
        self.assertIn("900", offset_fn)
        self.assertIn("return(0);", offset_fn)

        # 2. PublishMarket converts tick.time_msc using ServerUtcOffsetSeconds() and guards <= 0
        self.assertIn("ServerUtcOffsetSeconds()", pub_fn)
        self.assertIn("(long)tick.time_msc - srv_offset_ms", pub_fn)
        self.assertIn("if(tick_utc_msc <= 0)", pub_fn)
        self.assertIsNone(re.search(r"IntegerToString\s*\(\s*\(long\)\s*tick\.time_msc\s*\)", pub_fn))

        # 3. CandleSeriesJson converts rates[i].time using ServerUtcOffsetSeconds() and guards <= 0
        self.assertIn("ServerUtcOffsetSeconds()", candles_fn)
        self.assertIn("(long)rates[i].time - srv_offset_s", candles_fn)
        self.assertIn("if(bar_utc_s <= 0)", candles_fn)
        self.assertIn("TimeToStruct((datetime)bar_utc_s, dt)", candles_fn)
        self.assertIsNone(re.search(r"TimeToStruct\s*\(\s*rates\[i\]\.time", candles_fn))

        # 4. Python mirror formula across timezones and fail-closed boundary inputs
        base = 1795391922
        for delta, expected in (
            (10800, 10800),
            (10799, 10800),
            (10801, 10800),
            (7200, 7200),
            (0, 0),
            (-1, 0),
            (1, 0),
            (-18000, -18000),
            (-18001, -18000),
            (-17999, -18000),
            (19800, 19800),   # UTC+05:30
            (20700, 20700),   # UTC+05:45
            (50400, 50400),   # UTC+14:00
            (-43200, -43200), # UTC-12:00
            (60000, 0),       # Out-of-range fails closed to 0
            (-60000, 0),      # Out-of-range fails closed to 0
        ):
            self.assertEqual(_py_server_utc_offset_seconds(base + delta, base), expected)
        self.assertEqual(_py_server_utc_offset_seconds(0, base), 0)
        self.assertEqual(_py_server_utc_offset_seconds(base, 0), 0)

        # 5. Python transport default max_future_skew_seconds remains strictly 5.0
        sig = inspect.signature(Mt5SpoolBridgeTransport.__init__)
        self.assertEqual(sig.parameters["max_future_skew_seconds"].default, 5.0)

    def test_gmt_plus_3_raw_tick_rejected_and_utc_converted_tick_accepted(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            spool = Path(td) / "lhfx_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool,
                server="LHFXSA-Trade",
                login=122590,
                quotes={"NAS100": (D("25786.99"), D("25791.27"))},
                balance=D("97478.59"),
                clock=clock,
            )
            emu.publish_market()
            tr = Mt5SpoolBridgeTransport(spool, sleep=emu.sleep_hook, poll_interval_seconds=0.01, clock=clock)
            tr.connect(Mt5Credentials(BROKER_LHFX_MT5, 122590, "LHFXSA-Trade"))

            base_doc = json.loads((spool / "market_ticks.json").read_text(encoding="utf-8"))
            now_ms = int(clock().timestamp() * 1000)

            # (a) Raw GMT+3 broker server time_msc (+10,800s ahead of UTC) STILL fails closed
            raw_srv_ms = now_ms + 10_800_000
            bad_doc = dict(base_doc)
            bad_doc["ticks"] = [{
                "symbol": "NAS100",
                "bid": "25786.99",
                "ask": "25791.27",
                "time_msc": str(raw_srv_ms),
            }]
            signed_bad = sign_mt5_market_snapshot_doc(bad_doc, spool_dir=spool, snapshot_seq=2, observed_at=clock())
            (spool / "market_ticks.json").write_text(json.dumps(signed_bad), encoding="utf-8")

            with self.assertRaises(Mt5SnapshotIntegrityError):
                tr.symbol_tick("NAS100")
            found_bad, errs_bad = tr.symbol_ticks_batch(("NAS100",))
            self.assertEqual(found_bad, {})
            self.assertEqual(errs_bad["NAS100"], "Mt5SnapshotIntegrityError")

            # (b) Subtracting ServerUtcOffsetSeconds(GMT+3)=10,800s yields valid UTC time_msc
            offset_ms = _py_server_utc_offset_seconds(int(clock().timestamp()) + 10800, int(clock().timestamp())) * 1000
            utc_ms = raw_srv_ms - offset_ms
            good_doc = dict(base_doc)
            good_doc["ticks"] = [{
                "symbol": "NAS100",
                "bid": "25786.99",
                "ask": "25791.27",
                "time_msc": str(utc_ms),
            }]
            signed_good = sign_mt5_market_snapshot_doc(good_doc, spool_dir=spool, snapshot_seq=3, observed_at=clock())
            (spool / "market_ticks.json").write_text(json.dumps(signed_good), encoding="utf-8")

            tick = tr.symbol_tick("NAS100")
            self.assertEqual(tick.bid, D("25786.99"))
            self.assertEqual(tick.ask, D("25791.27"))
            found_ok, errs_ok = tr.symbol_ticks_batch(("NAS100",))
            self.assertEqual(errs_ok, {})
            self.assertEqual(found_ok["NAS100"], tick)

            # (c) Weekend stale Friday tick (48h old in GMT+3) STILL fails freshness check after -10,800s conversion
            friday_srv_ms = (now_ms - 172_800_000) + 10_800_000
            stale_utc_ms = friday_srv_ms - offset_ms
            stale_doc = dict(base_doc)
            stale_doc["ticks"] = [{
                "symbol": "NAS100",
                "bid": "25786.99",
                "ask": "25791.27",
                "time_msc": str(stale_utc_ms),
            }]
            signed_stale = sign_mt5_market_snapshot_doc(stale_doc, spool_dir=spool, snapshot_seq=4, observed_at=clock())
            (spool / "market_ticks.json").write_text(json.dumps(signed_stale), encoding="utf-8")

            with self.assertRaises(Mt5SnapshotIntegrityError):
                tr.symbol_tick("NAS100", require_fresh_tick=True)

    def test_dual_shield_snapshot_unverified_recovers_only_after_verified_probe(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            emu_h = Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=1002903,
                quotes={"EURUSD": (D("1.10000"), D("1.10010"))},
                balance=D("0.00"),
                clock=clock,
            )
            emu_h.set_connected(False)
            emu_h.publish_market()

            emu_l = Mt5SpoolPaperTerminalEmulator(
                root / "lhfx_mt5",
                server="LHFXSA-Trade",
                login=122590,
                quotes={"EURUSD": (D("1.10000"), D("1.10010"))},
                balance=D("97478.59"),
                clock=clock,
            )
            emu_l.publish_market()

            gate = load_default_forex_valve_gate()
            oanda = _StubOandaTransport()
            env = {
                ENV_MT5_TRANSPORT_MODE: TRANSPORT_SPOOL_BRIDGE,
                ENV_MT5_SPOOL_DIR: str(root),
                ENV_HUGOSWAY_MT5_LOGIN: "1002903",
                ENV_HUGOSWAY_MT5_PASSWORD: _test_fixture_val("hugo"),
                ENV_HUGOSWAY_MT5_SERVER: "Hugosway-Demo",
                ENV_LHFX_MT5_LOGIN: "122590",
                ENV_LHFX_MT5_SERVER: "LHFXSA-Trade",
                ENV_OANDA_PRACTICE_TOKEN: _test_fixture_val("oanda"),
                ENV_OANDA_PRACTICE_ACCOUNT_ID: oanda.account_id,
            }
            emus = {BROKER_HUGOSWAY_MT5: emu_h, BROKER_LHFX_MT5: emu_l}
            router = DualShieldBrokerRouter(
                environ=env,
                valve_gate=gate,
                peak_equity_store=gate.peak_equity_store,
                transport_factory=lambda bid, _m, r: Mt5SpoolBridgeTransport(
                    Path(r) / bid.lower(), sleep=emus[bid].sleep_hook, poll_interval_seconds=0.01, clock=clock
                ),
                oanda_client_factory=lambda e: OandaPracticePaperClient.from_runtime_env(e, transport=oanda, clock=clock),
                clock=clock,
            )
            router.activate_all()
            snap_init = router.routing_snapshot()
            row_l = next(r for r in snap_init["chain"] if r["broker_id"] == BROKER_LHFX_MT5)
            self.assertEqual(row_l["status"], "ACTIVE")

            # 1. Tamper LHFX market_ticks.json (or trigger integrity error) -> SNAPSHOT_UNVERIFIED / SNAPSHOT_INTEGRITY_FAILED
            lhfx_ticks = root / "lhfx_mt5" / "market_ticks.json"
            good_raw = lhfx_ticks.read_bytes()
            tampered = json.loads(good_raw.decode("utf-8"))
            tampered["account"]["equity"] = "9999999.00"
            lhfx_ticks.write_text(json.dumps(tampered), encoding="utf-8")

            snap_bad = router.routing_snapshot()
            row_bad = next(r for r in snap_bad["chain"] if r["broker_id"] == BROKER_LHFX_MT5)
            self.assertEqual(row_bad["status"], "SNAPSHOT_UNVERIFIED")
            self.assertEqual(row_bad["failure"], "SNAPSHOT_INTEGRITY_FAILED")

            # 2. Missing/unreadable spool file (OSError / ContractError during probe) MUST NOT clear SNAPSHOT_UNVERIFIED
            lhfx_ticks.unlink()
            snap_missing = router.routing_snapshot()
            row_missing = next(r for r in snap_missing["chain"] if r["broker_id"] == BROKER_LHFX_MT5)
            self.assertEqual(row_missing["status"], "SNAPSHOT_UNVERIFIED")
            self.assertEqual(row_missing["failure"], "SNAPSHOT_INTEGRITY_FAILED")

            # 3. Publish fresh valid monotonic HMAC-signed snapshot -> probe verifies -> recovers to ACTIVE cleanly
            clock.advance(2)
            emu_l.publish_market()
            snap_rec = router.routing_snapshot()
            row_rec = next(r for r in snap_rec["chain"] if r["broker_id"] == BROKER_LHFX_MT5)
            self.assertEqual(row_rec["status"], "ACTIVE")
            self.assertIsNone(row_rec["failure"])
            self.assertEqual(router.equities()[BROKER_LHFX_MT5], D("97478.59"))

            # 4. Subsequent integrity failure STILL demotes to SNAPSHOT_UNVERIFIED and refuses execute_open()
            tampered2 = json.loads(lhfx_ticks.read_text(encoding="utf-8"))
            tampered2["account"]["equity"] = "5555555.00"
            lhfx_ticks.write_text(json.dumps(tampered2), encoding="utf-8")
            snap_bad2 = router.routing_snapshot()
            row_bad2 = next(r for r in snap_bad2["chain"] if r["broker_id"] == BROKER_LHFX_MT5)
            self.assertEqual(row_bad2["status"], "SNAPSHOT_UNVERIFIED")
            self.assertEqual(row_bad2["failure"], "SNAPSHOT_INTEGRITY_FAILED")

            order = OrderIntent(
                order_id="pr36-refuse-tampered-1",
                action_ref="act-pr36-tamper-1",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
                limit_price=D("1.10010"),
            )
            dec = _admit_open_order(gate, order, now=clock())
            with self.assertRaises(Mt5SnapshotIntegrityError):
                router.execute_open(order, valve_decision=dec)


if __name__ == "__main__":
    unittest.main()
