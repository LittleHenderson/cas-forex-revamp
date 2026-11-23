"""PR #37 regression & performance tests: MT5 signed order_history reconciliation, single-pass equity, fast metrics, and offline log suppression."""
from __future__ import annotations

from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from cas_forex_revamp.composition.autonomous_trader import AutonomousAiTrader
from cas_forex_revamp.composition.live_cockpit_server import _build_mt5_index_snapshot_from_router
from cas_forex_revamp.contracts import ActionKind, Side
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
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
    Mt5MutationJournal,
    Mt5SnapshotIntegrityError,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    Mt5Tick,
    Mt5TransportError,
    OrderIntent,
    TRANSPORT_SPOOL_BRIDGE,
    _atomic_write_json,
    _load_or_create_spool_hmac_key,
    _spool_hmac_hex,
    _canonical_spool_order_history_hmac_input,
    sign_mt5_order_history_doc,
)

D = Decimal
T0 = datetime(2026, 11, 23, 2, 0, 0, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[2]
MQ5_PATH = REPO_ROOT / "mt5" / "CasForexMt5Bridge.mq5"


def _fixture_str(slot: str) -> str:
    return f"pr37-fixture-{slot}"


class _MutableClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int | float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


class _MutableMono:
    def __init__(self, start: float = 100.0) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> float:
        self.now += float(seconds)
        return self.now


class _StubOandaTransport:
    def __init__(self, *, account_id: str = "101-001-3700001-001", equity: str = "100000.00") -> None:
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
    sel = SimpleNamespace(evidence_ids=("ev-1",), reason="pr37 test", selected_action_ref=order.action_ref)
    prop = SimpleNamespace(request=req, result=SimpleNamespace(selection=sel), intent=intent)
    view = {"balance": "100000", "equity": "100000", "available_margin": "90000", "position_inventory": "[]"}
    pol = {"new_risk_permission": "ALLOWED", "management_permission": "ALLOWED", "max_entry_quantity": "10000000"}
    return gate.require_admissible(prop, current_view=view, policy=pol, now=now)


class Pr37Mt5HistoryReconcileAndPerfTests(unittest.TestCase):
    def test_mql5_publish_order_history_parity(self) -> None:
        mq5 = MQ5_PATH.read_text(encoding="utf-8")
        hist_fn = _extract_mql5_fn(mq5, "void PublishOrderHistory()")
        safe_fn = _extract_mql5_fn(mq5, "string SafeHistText(")
        iso_fn = _extract_mql5_fn(mq5, "string IsoFromUtcSeconds(")
        init_fn = _extract_mql5_fn(mq5, "int OnInit()")
        timer_fn = _extract_mql5_fn(mq5, "void OnTimer()")
        proc_fn = _extract_mql5_fn(mq5, "void ProcessRequests()")

        for required in (
            "HistorySelect",
            "HistoryOrdersTotal",
            "HistoryDealsTotal",
            "MAX_HIST_ROWS = 600",
            "g_hmac_key",
            "g_channel_key_id",
            "open_position_tickets",
            "history_hmac_sha256",
            'WriteAtomic("order_history.json", json)',
        ):
            self.assertIn(required, hist_fn)
        self.assertIn("TimeToStruct((datetime)utc_s", iso_fn)
        for ch in ('"|"', '";"', '":"'):
            self.assertIn(ch, safe_fn)
        self.assertIn("PublishOrderHistory();", init_fn)
        self.assertIn("PublishOrderHistory();", timer_fn)
        self.assertIn("g_history_dirty = true;", proc_fn)

        # Canonical message field parity between Python and MQL5 PublishOrderHistory()
        canon = _canonical_spool_order_history_hmac_input({
            "protocol": "cas-forex-mt5-spool/2",
            "broker_channel": "lhfx_mt5",
            "channel_key_id": "0123456789abcdef",
            "execution_mode": "DEMO",
            "account_login": "122590",
            "server": "LHFXSA-Trade",
            "account_trade_mode": "DEMO",
            "connected": True,
            "complete": True,
            "observed_at": "2026-11-23T02:00:00Z",
            "open_position_tickets": ["101"],
            "orders": [{"order_ticket": "10", "request_id": "r1", "symbol": "NAS100", "time_utc": "2026-11-23T01:59:00Z"}],
            "deals": [{"deal_ticket": "20", "order_ticket": "10", "request_id": "r1", "symbol": "NAS100", "time_utc": "2026-11-23T01:59:01Z"}],
        })
        parts = canon.split("|")
        self.assertEqual(len(parts), 13)
        self.assertEqual(parts[0:10], [
            "cas-forex-mt5-spool/2", "lhfx_mt5", "0123456789abcdef", "DEMO",
            "122590", "LHFXSA-Trade", "DEMO", "true", "true", "2026-11-23T02:00:00Z",
        ])
        for digest_part in parts[10:13]:
            self.assertEqual(len(digest_part), 64)

    def test_spool_order_history_security_guards_and_reconciliation(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            journal_db = root / "state.sqlite3"
            journal = Mt5MutationJournal(journal_db)
            journal.record_pending(
                request_id="lhfx_mt5-000043-d9a0f54ad3018033",
                broker_id=BROKER_LHFX_MT5,
                account_login=122590,
                server="LHFXSA-Trade",
                symbol="NAS100",
                action_kind="AMEND_STOP",
                position_ticket="13701842",
                semantic_key="AMEND_STOP|LHFX_MT5|122590|LHFXSA-Trade|NAS100|13701842",
                now_utc="2026-11-19T16:14:24Z",
            )
            journal.mark_outcome(
                request_id="lhfx_mt5-000043-d9a0f54ad3018033",
                status="OUTCOME_UNKNOWN",
                now_utc="2026-11-19T16:14:24Z",
                error_detail="Mt5TransportError",
            )

            emu_h = Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=1002903,
                quotes={"NAS100": (D("25750.00"), D("25752.00")), "EURUSD": (D("1.10000"), D("1.10010"))},
                balance=D("0.00"),
                connected=False,
                clock=clock,
            )
            emu_h.publish_market()

            emu_l = Mt5SpoolPaperTerminalEmulator(
                root / "lhfx_mt5",
                server="LHFXSA-Trade",
                login=122590,
                quotes={"NAS100": (D("25750.00"), D("25752.00")), "EURUSD": (D("1.10000"), D("1.10010"))},
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
                ENV_HUGOSWAY_MT5_PASSWORD: _fixture_str("hugo"),
                ENV_HUGOSWAY_MT5_SERVER: "Hugosway-Demo",
                ENV_LHFX_MT5_LOGIN: "122590",
                ENV_LHFX_MT5_SERVER: "LHFXSA-Trade",
                ENV_OANDA_PRACTICE_TOKEN: _fixture_str("oanda"),
                ENV_OANDA_PRACTICE_ACCOUNT_ID: oanda.account_id,
                "CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE": "1",
            }
            emus = {BROKER_HUGOSWAY_MT5: emu_h, BROKER_LHFX_MT5: emu_l}
            router = DualShieldBrokerRouter(
                environ=env,
                valve_gate=gate,
                peak_equity_store=gate.peak_equity_store,
                mt5_mutation_journal=journal,
                transport_factory=lambda bid, _m, r: Mt5SpoolBridgeTransport(
                    Path(r) / bid.lower(), sleep=emus[bid].sleep_hook, poll_interval_seconds=0.01, clock=clock
                ),
                oanda_client_factory=lambda e: OandaPracticePaperClient.from_runtime_env(e, transport=oanda, clock=clock),
                clock=clock,
            )
            router.activate_all()
            elig0, reason0 = router.check_open_eligibility("NAS100")
            self.assertFalse(elig0)
            self.assertEqual(reason0, "UNRESOLVED_MUTATION_LATCH")

            lhfx_venue = router.venues[BROKER_LHFX_MT5]
            hist_path = root / "lhfx_mt5" / "order_history.json"
            master_key = _load_or_create_spool_hmac_key(root / "lhfx_mt5")
            base_doc = emu_l.publish_order_history()

            # 1. Forged HMAC fails closed
            forged = dict(base_doc)
            forged["history_hmac_sha256"] = "0" * 64
            _atomic_write_json(hist_path, forged)
            with self.assertRaises(Mt5SnapshotIntegrityError):
                lhfx_venue.reconcile_unknown_mutations(now=clock())
            rec_forged = router.reconcile_unknown_mutations(now=clock())
            self.assertEqual(rec_forged["remaining_unknown"], 1)

            # 2. Legacy master-key HMAC (bypass attempt against Finding [7]) MUST fail closed
            legacy_doc = dict(base_doc)
            legacy_doc["history_hmac_sha256"] = _spool_hmac_hex(
                master_key, _canonical_spool_order_history_hmac_input(legacy_doc)
            )
            _atomic_write_json(hist_path, legacy_doc)
            with self.assertRaises(Mt5SnapshotIntegrityError):
                lhfx_venue.reconcile_unknown_mutations(now=clock())

            # 3. Wrong channel, wrong server, wrong login, incomplete, disconnected, stale ALL fail closed
            for mut_patch, exc_type in (
                ({"broker_channel": "hugosway_mt5"}, Mt5SnapshotIntegrityError),
                ({"server": "Wrong-Demo"}, Mt5SnapshotIntegrityError),
                ({"account_login": "999999"}, Mt5SnapshotIntegrityError),
                ({"complete": False}, Mt5SnapshotIntegrityError),
                ({"connected": False}, Mt5TransportError),
                ({"observed_at": (clock() - timedelta(seconds=180)).isoformat().replace("+00:00", "Z")}, Mt5SnapshotIntegrityError),
            ):
                bad = dict(base_doc)
                bad.update(mut_patch)
                bad_signed = sign_mt5_order_history_doc(
                    bad, spool_dir=root / "lhfx_mt5", broker_channel=str(bad.get("broker_channel") or "lhfx_mt5")
                )
                _atomic_write_json(hist_path, bad_signed)
                with self.assertRaises(exc_type):
                    lhfx_venue.reconcile_unknown_mutations(now=clock())
                self.assertEqual(len(journal.list_unresolved_mutations()), 1)

            # 4. Target position still open in order_history.json keeps AMEND_STOP latch blocked
            emu_l._positions["13701842"] = {
                "symbol": "NAS100", "side": Side.BUY, "volume": D("0.10"),
                "price_open": D("25700.00"), "sl": D("25650.00"), "tp": None,
            }
            emu_l.publish_order_history()
            rec_still_open = router.reconcile_unknown_mutations(now=clock())
            self.assertEqual(rec_still_open["remaining_unknown"], 1)
            self.assertTrue(router.has_any_unresolved_mutation())

            # 5. Target position 13701842 closed -> verified order_history.json clears latch cleanly even with HUGOSWAY_MT5 offline
            emu_l._positions.clear()
            emu_l.publish_order_history()
            rec_clear = router.reconcile_unknown_mutations(now=clock())
            self.assertEqual(rec_clear["resolved"], 1)
            self.assertEqual(rec_clear["remaining_unknown"], 0)
            self.assertFalse(rec_clear["has_unresolved_mutation"])
            elig1, reason1 = router.check_open_eligibility("NAS100")
            self.assertTrue(elig1)
            self.assertEqual(reason1, "ELIGIBLE:LHFX_MT5")

            # 6. Matching via 31-char MT5 order comment format cas-<tail> confirms FILLED (and clears journal);
            # ambiguous unmatched OPEN order in time window stays OUTCOME_UNKNOWN
            fill_id = "lhfx_mt5-000100-fedcba9876543210"
            journal.record_pending(
                request_id=fill_id,
                broker_id=BROKER_LHFX_MT5,
                account_login=122590,
                server="LHFXSA-Trade",
                symbol="SPX500",
                action_kind="OPEN",
                position_ticket=None,
                semantic_key="OPEN|LHFX_MT5|122590|LHFXSA-Trade|SPX500|",
                now_utc=clock().isoformat().replace("+00:00", "Z"),
            )
            journal.mark_outcome(request_id=fill_id, status="OUTCOME_UNKNOWN", now_utc=clock().isoformat().replace("+00:00", "Z"))
            emu_l._history_orders.append({
                "order_ticket": "88802",
                "request_id": f"cas-{fill_id[-27:]}"[:31],
                "symbol": "SPX500",
                "time_utc": clock().isoformat().replace("+00:00", "Z"),
            })
            emu_l._history_deals.append({
                "deal_ticket": "99902",
                "order_ticket": "88802",
                "request_id": f"cas-{fill_id[-27:]}"[:31],
                "symbol": "SPX500",
                "time_utc": clock().isoformat().replace("+00:00", "Z"),
            })
            emu_l.publish_order_history()
            rec_fill = router.reconcile_unknown_mutations(now=clock())
            self.assertEqual(rec_fill["resolved"], 1)
            self.assertEqual(rec_fill["remaining_unknown"], 0)
            self.assertFalse(router.has_any_unresolved_mutation())

            amb_id = "lhfx_mt5-000099-abcdef0123456789"
            journal.record_pending(
                request_id=amb_id,
                broker_id=BROKER_LHFX_MT5,
                account_login=122590,
                server="LHFXSA-Trade",
                symbol="US30",
                action_kind="OPEN",
                position_ticket=None,
                semantic_key="OPEN|LHFX_MT5|122590|LHFXSA-Trade|US30|",
                now_utc=clock().isoformat().replace("+00:00", "Z"),
            )
            journal.mark_outcome(request_id=amb_id, status="OUTCOME_UNKNOWN", now_utc=clock().isoformat().replace("+00:00", "Z"))
            emu_l._history_orders.append({
                "order_ticket": "88801",
                "request_id": "",
                "symbol": "US30",
                "time_utc": clock().isoformat().replace("+00:00", "Z"),
            })
            emu_l.publish_order_history()
            rec_amb = router.reconcile_unknown_mutations(now=clock())
            self.assertEqual(rec_amb["remaining_unknown"], 1)
            self.assertTrue(router.has_any_unresolved_mutation())

    def test_single_pass_equity_bundle_fast_metrics_and_offline_log_suppression(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            emu_h = Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=1002903,
                quotes={"NAS100": (D("25750.00"), D("25752.00"))},
                balance=D("0.00"),
                connected=False,
                clock=clock,
            )
            emu_h.publish_market()
            emu_l = Mt5SpoolPaperTerminalEmulator(
                root / "lhfx_mt5",
                server="LHFXSA-Trade",
                login=122590,
                quotes={
                    "NAS100": (D("25750.00"), D("25752.00")),
                    "US30": (D("48950.00"), D("48954.00")),
                    "SPX500": (D("7060.00"), D("7060.75")),
                    "XAUUSD": (D("3605.00"), D("3605.50")),
                },
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
                ENV_HUGOSWAY_MT5_PASSWORD: _fixture_str("hugo"),
                ENV_HUGOSWAY_MT5_SERVER: "Hugosway-Demo",
                ENV_LHFX_MT5_LOGIN: "122590",
                ENV_LHFX_MT5_SERVER: "LHFXSA-Trade",
                ENV_OANDA_PRACTICE_TOKEN: _fixture_str("oanda"),
                ENV_OANDA_PRACTICE_ACCOUNT_ID: oanda.account_id,
                "CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE": "1",
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
            reg = FrontierModelRegistry(environ={})
            quota = DailyQuotaGovernanceStore(root / "quota.sqlite3")
            exec_gate = DurableModelExecutionGate(db_path=root / "model_gate.sqlite3")
            trader = AutonomousAiTrader(
                router=router,
                model_registry=reg,
                valve_gate=gate,
                quota_store=quota,
                peak_equity_store=gate.peak_equity_store,
                execution_gate=exec_gate,
                state_dir=root / "trader_state",
                clock=clock,
            )

            # 1. Single-pass _router_equity_bundle_unlocked calls equities() once and skips offline_brokers()/online_equities()
            with (
                mock.patch.object(router, "equities", wraps=router.equities) as w_eq,
                mock.patch.object(router, "offline_brokers", wraps=router.offline_brokers) as w_off,
                mock.patch.object(router, "online_equities", wraps=router.online_equities) as w_on,
                mock.patch.object(router.venues[BROKER_LHFX_MT5], "probe", wraps=router.venues[BROKER_LHFX_MT5].probe) as w_probe,
            ):
                bundle = trader._router_equity_bundle_unlocked()
                self.assertEqual(w_eq.call_count, 1)
                self.assertEqual(w_off.call_count, 0)
                self.assertEqual(w_on.call_count, 0)
                self.assertEqual(bundle["offline_brokers"], [BROKER_HUGOSWAY_MT5])
                self.assertEqual(bundle["online_total_eq"], D("197478.59"))

                # evaluate_fast_protection does NOT call extra venue.probe() for Mt5SpoolBridgeTransport on DualShieldBrokerRouter
                w_eq.reset_mock()
                w_off.reset_mock()
                w_probe.reset_mock()
                trader.run_fast_tick_cycle(mt5_quotes={
                    "NAS100": (D("25750.00"), D("25752.00")),
                    "US30": (D("48950.00"), D("48954.00")),
                })
                self.assertEqual(w_eq.call_count, 1)
                self.assertEqual(w_off.call_count, 0)
                self.assertEqual(w_probe.call_count, 1)

                # metrics_summary() and dial_context_summary() make ZERO equities() or status_snapshot() calls
                w_eq.reset_mock()
                with mock.patch.object(trader, "status_snapshot", side_effect=AssertionError("should not call status_snapshot")):
                    msum = trader.metrics_summary()
                    dctx = trader.dial_context_summary()
                self.assertEqual(w_eq.call_count, 0)
                self.assertEqual(msum["cycle_count"], 1)
                self.assertIn("effective_status", msum)
                self.assertIn("drawdown_pct", dctx)
                self.assertFalse(trader.has_open_positions_fast())

            # 2. _build_mt5_index_snapshot_from_router suppresses HUGOSWAY_MT5 skip logs when LHFX_MT5 provides all 4 index quotes
            buf = io.StringIO()
            poll_cache: dict[str, dict[str, object]] = {}
            log_throttle: dict[tuple[str, str, str], tuple[float, int]] = {}
            mono = _MutableMono()
            with redirect_stdout(buf):
                snap, q_out = _build_mt5_index_snapshot_from_router(
                    router,
                    prev_stream=None,
                    poll_cache=poll_cache,
                    log_throttle=log_throttle,
                    mono_clock=mono,
                )
            self.assertIsNotNone(snap)
            self.assertEqual(set(q_out.keys()), {"NAS100", "US30", "SPX500", "XAUUSD"})
            self.assertEqual(buf.getvalue().strip(), "")


if __name__ == "__main__":
    unittest.main()
