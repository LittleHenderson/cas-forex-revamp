"""Unit tests for Phase 8 Clear Street Item 2: ExecutionEventBus & Mt5PositionDiffEmitter."""

from __future__ import annotations

from decimal import Decimal
import json
import threading
import time
import unittest

from cas_forex_revamp.contracts import Side
from cas_forex_revamp.venue.execution_event_bus import (
    ExecutionEvent,
    ExecutionEventBus,
    ExecutionEventType,
    Mt5PositionDiffEmitter,
    SubscriberLane,
)
from cas_forex_revamp.venue.mt5_broker_bridge import BROKER_HUGOSWAY_MT5, Mt5Position


def _make_event(
    event_id: str,
    *,
    event_type: ExecutionEventType = ExecutionEventType.FILL,
    broker_id: str = BROKER_HUGOSWAY_MT5,
    symbol: str = "EURUSD",
    order_id: str = "ord-1001",
    position_ticket: str = "5001",
    side: str | Side = Side.BUY,
    quantity_lots: Decimal = Decimal("0.25"),
    price: Decimal = Decimal("1.08500"),
    realized_pnl_usd: Decimal = Decimal("0.00"),
    timestamp_utc: str = "2026-11-20T06:52:37.000000Z",
    stop_loss: Decimal | None = Decimal("1.08000"),
    take_profit: Decimal | None = Decimal("1.09500"),
    reason: str = "",
) -> ExecutionEvent:
    return ExecutionEvent(
        event_id=event_id,
        event_type=event_type,
        broker_id=broker_id,
        symbol=symbol,
        order_id=order_id,
        position_ticket=position_ticket,
        side=side,
        quantity_lots=quantity_lots,
        price=price,
        realized_pnl_usd=realized_pnl_usd,
        timestamp_utc=timestamp_utc,
        stop_loss=stop_loss,
        take_profit=take_profit,
        reason=reason,
    )


def _eventbus_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name.startswith("cas-eventbus-")]


class ExecutionEventModelTests(unittest.TestCase):
    def test_all_event_types_and_immutability(self) -> None:
        expected = {
            "FILL",
            "PARTIAL_FILL",
            "SL_HIT",
            "TP_HIT",
            "CANCELLED",
            "AMEND_STOP",
            "REJECTED",
            "CLOSE_MANUAL",
        }
        self.assertEqual({et.value for et in ExecutionEventType}, expected)

        ev = _make_event("evt-immutable")
        with self.assertRaises(AttributeError):
            ev.symbol = "GBPUSD"  # type: ignore[misc]

    def test_decimal_strictness_rejects_floats_and_nonfinite(self) -> None:
        with self.assertRaises(TypeError):
            _make_event("evt-float-qty", quantity_lots=0.25)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            _make_event("evt-float-px", price=1.085)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            _make_event("evt-float-pnl", realized_pnl_usd=12.5)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            _make_event("evt-nan-px", price=Decimal("NaN"))
        with self.assertRaises(ValueError):
            _make_event("evt-neg-qty", quantity_lots=Decimal("-0.10"))

    def test_deterministic_payload_sha256_and_tamper_detection(self) -> None:
        ev1 = _make_event(
            "evt-hash-1",
            quantity_lots=Decimal("0.2500"),
            price=Decimal("1.08500"),
            realized_pnl_usd=Decimal("0.00"),
        )
        ev2 = _make_event(
            "evt-hash-1",
            quantity_lots=Decimal("0.25"),
            price=Decimal("1.085"),
            realized_pnl_usd=Decimal("0"),
        )
        self.assertEqual(len(ev1.payload_sha256), 64)
        self.assertEqual(ev1.payload_sha256, ev2.payload_sha256)
        self.assertTrue(ev1.verify_payload_sha256())

        stamped = ev1.with_seq_id(42)
        self.assertEqual(stamped.seq_id, 42)
        self.assertEqual(stamped.payload_sha256, ev1.payload_sha256)
        self.assertTrue(stamped.verify_payload_sha256())

        with self.assertRaises(ValueError):
            ExecutionEvent(
                event_id="evt-tampered",
                event_type=ExecutionEventType.FILL,
                broker_id=BROKER_HUGOSWAY_MT5,
                symbol="EURUSD",
                order_id="ord-1",
                position_ticket="5001",
                side=Side.BUY,
                quantity_lots=Decimal("0.10"),
                price=Decimal("1.0850"),
                realized_pnl_usd=Decimal("0"),
                timestamp_utc="2026-11-20T06:52:37.000000Z",
                payload_sha256="0" * 64,
            )

    def test_to_sse_frame_sanitizes_control_char_and_newline_injection(self) -> None:
        malicious_unstamped = _make_event(
            "evt-1\r\nevent: FORGED\ndata: {\"pwn\":true}\u2028\x00",
            symbol="EURUSD\r\nX-Injected: 1",
            order_id="ord-1\nfake",
            reason="line1\r\nline2\u2029\x07",
        )
        frame = malicious_unstamped.to_sse_frame()
        self.assertTrue(frame.endswith("\n\n"))
        self.assertNotIn("\r", frame)
        self.assertNotIn("\x00", frame)
        self.assertNotIn("\u2028", frame)
        self.assertNotIn("\u2029", frame)

        lines = frame[:-2].split("\n")
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[0].startswith("id: "))
        self.assertNotIn("\n", lines[0])
        self.assertEqual(lines[1], "event: FILL")
        self.assertTrue(lines[2].startswith("data: "))

        parsed = json.loads(lines[2][len("data: ") :])
        self.assertEqual(parsed["quantity_lots"], "0.25")
        self.assertEqual(parsed["price"], "1.085")
        self.assertEqual(parsed["payload_sha256"], malicious_unstamped.payload_sha256)

        stamped = malicious_unstamped.with_seq_id(7)
        stamped_frame = stamped.to_sse_frame()
        stamped_lines = stamped_frame[:-2].split("\n")
        self.assertEqual(len(stamped_lines), 3)
        self.assertEqual(stamped_lines[0], "id: 7")
        self.assertEqual(stamped_lines[1], "event: FILL")
        parsed_stamped = json.loads(stamped_lines[2][len("data: ") :])
        self.assertEqual(parsed_stamped["seq_id"], 7)


class ExecutionEventBusTests(unittest.TestCase):
    def test_monotonic_seq_id_and_idempotency_dedup(self) -> None:
        critical_seen: list[ExecutionEvent] = []
        ledger_seen: list[ExecutionEvent] = []

        with ExecutionEventBus() as bus:
            bus.subscribe(critical_seen.append, lane=SubscriberLane.CRITICAL_PROTECTION)
            bus.subscribe(ledger_seen.append, lane=SubscriberLane.LEDGER_ASYNC)

            e1 = bus.publish(_make_event("evt-dup-1"))
            e1_dup = bus.publish(_make_event("evt-dup-1"))
            e2 = bus.publish(_make_event("evt-dup-2", event_type=ExecutionEventType.TP_HIT, realized_pnl_usd=Decimal("125.50")))
            e2_dup, is_new = bus.publish_idempotent(_make_event("evt-dup-2", event_type=ExecutionEventType.TP_HIT, realized_pnl_usd=Decimal("125.50")))

            self.assertEqual(e1.seq_id, 1)
            self.assertEqual(e1_dup.seq_id, 1)
            self.assertEqual(e1_dup, e1)
            self.assertEqual(e2.seq_id, 2)
            self.assertEqual(e2_dup.seq_id, 2)
            self.assertFalse(is_new)

            self.assertTrue(bus.flush(timeout=2.0))
            self.assertEqual([ev.seq_id for ev in critical_seen], [1, 2])
            self.assertEqual([ev.seq_id for ev in ledger_seen], [1, 2])

            m = bus.metrics()
            self.assertEqual(m["published_count"], 2)
            self.assertEqual(m["deduped_count"], 2)
            self.assertEqual(m["dropped_events"], 0)
            self.assertEqual(m["subscriber_errors"], 0)
            self.assertEqual(m["last_seq_id"], 2)

        self.assertEqual(_eventbus_threads(), [])

    def test_fault_isolation_and_publish_latency_under_50ms(self) -> None:
        critical_events: list[ExecutionEvent] = []
        healthy_ledger_events: list[ExecutionEvent] = []
        healthy_ui_events: list[ExecutionEvent] = []
        slow_started = threading.Event()

        def slow_ledger_subscriber(ev: ExecutionEvent) -> None:
            slow_started.set()
            time.sleep(0.40)

        def raising_ledger_subscriber(ev: ExecutionEvent) -> None:
            raise RuntimeError(f"simulated ledger db crash on {ev.event_id}")

        def raising_ui_subscriber(ev: ExecutionEvent) -> None:
            raise RuntimeError(f"simulated sse socket disconnect on {ev.event_id}")

        def raising_critical_subscriber(ev: ExecutionEvent) -> None:
            raise RuntimeError(f"simulated non-fatal critical hook error on {ev.event_id}")

        with ExecutionEventBus() as bus:
            bus.subscribe(raising_critical_subscriber, lane=SubscriberLane.CRITICAL_PROTECTION, name="bad-crit")
            bus.subscribe(critical_events.append, lane=SubscriberLane.CRITICAL_PROTECTION, name="good-crit")
            slow_id = bus.subscribe(slow_ledger_subscriber, lane=SubscriberLane.LEDGER_ASYNC, name="slow-ledger")
            bad_ledger_id = bus.subscribe(raising_ledger_subscriber, lane=SubscriberLane.LEDGER_ASYNC, name="bad-ledger")
            bad_ui_id = bus.subscribe(raising_ui_subscriber, lane=SubscriberLane.UI_SSE_ASYNC, name="bad-ui")
            bus.subscribe(healthy_ledger_events.append, lane=SubscriberLane.LEDGER_ASYNC, name="healthy-ledger")
            bus.subscribe(healthy_ui_events.append, lane=SubscriberLane.UI_SSE_ASYNC, name="healthy-ui")

            # Publish 3 events and measure each publish() + inline CRITICAL_PROTECTION completion.
            durations_ms: list[float] = []
            for idx in range(1, 4):
                ev = _make_event(
                    f"evt-iso-{idx}",
                    event_type=ExecutionEventType.AMEND_STOP,
                    stop_loss=Decimal("1.0850"),
                )
                t0 = time.perf_counter()
                stamped = bus.publish(ev)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                durations_ms.append(elapsed_ms)
                # CRITICAL_PROTECTION handler must already have processed this event synchronously.
                self.assertEqual(len(critical_events), idx)
                self.assertEqual(critical_events[-1].seq_id, stamped.seq_id)

            for elapsed_ms in durations_ms:
                self.assertLess(
                    elapsed_ms,
                    50.0,
                    f"publish() + CRITICAL_PROTECTION took {elapsed_ms:.2f}ms (limit < 50ms)",
                )

            # Wait briefly for fast healthy + raising async subscribers WITHOUT waiting 1.2s for slow_ledger.
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                m = bus.metrics()
                if (
                    len(healthy_ledger_events) == 3
                    and len(healthy_ui_events) == 3
                    and m["subscriber_errors"] >= 9
                ):
                    break
                time.sleep(0.01)

            self.assertTrue(slow_started.wait(timeout=1.0))
            self.assertEqual([e.seq_id for e in healthy_ledger_events], [1, 2, 3])
            self.assertEqual([e.seq_id for e in healthy_ui_events], [1, 2, 3])

            m = bus.metrics()
            # 3 events * (bad-crit + bad-ledger + bad-ui) = 9 errors.
            self.assertEqual(m["subscriber_errors"], 9)
            self.assertEqual(m["subscriber_errors_by_lane"][SubscriberLane.CRITICAL_PROTECTION.value], 3)
            self.assertEqual(m["subscriber_errors_by_lane"][SubscriberLane.LEDGER_ASYNC.value], 3)
            self.assertEqual(m["subscriber_errors_by_lane"][SubscriberLane.UI_SSE_ASYNC.value], 3)
            self.assertEqual(m["subscriber_errors_by_id"][bad_ledger_id], 3)
            self.assertEqual(m["subscriber_errors_by_id"][bad_ui_id], 3)
            self.assertEqual(m["subscriber_errors_by_id"][slow_id], 0)

        # After context-manager shutdown, slow worker finishes at most its single in-flight sleep and exits.
        self.assertEqual(_eventbus_threads(), [])

    def test_bounded_queue_backpressure_drop_oldest_and_drop_newest_without_deadlock(self) -> None:
        gate = threading.Event()
        started = threading.Event()
        received_oldest: list[int] = []
        received_newest: list[int] = []

        def blocked_oldest(ev: ExecutionEvent) -> None:
            started.set()
            gate.wait(timeout=2.0)
            received_oldest.append(ev.seq_id)

        def blocked_newest(ev: ExecutionEvent) -> None:
            gate.wait(timeout=2.0)
            received_newest.append(ev.seq_id)

        with ExecutionEventBus() as bus:
            sub_old = bus.subscribe(
                blocked_oldest,
                lane=SubscriberLane.UI_SSE_ASYNC,
                queue_maxsize=2,
                drop_policy="drop_oldest",
            )
            sub_new = bus.subscribe(
                blocked_newest,
                lane=SubscriberLane.UI_SSE_ASYNC,
                queue_maxsize=2,
                drop_policy="drop_newest",
            )

            # First event gets popped immediately by worker threads and blocks on gate.
            bus.publish(_make_event("bp-1"))
            self.assertTrue(started.wait(timeout=1.0))
            # Give second worker a brief moment to pop bp-1 too.
            time.sleep(0.05)

            # Publish 6 more events (seq 2..7) while both workers are blocked on seq 1.
            # With maxsize=2, 2 stay queued and exactly 4 overflow per subscriber (total 8 dropped).
            t0 = time.perf_counter()
            for i in range(2, 8):
                bus.publish(_make_event(f"bp-{i}"))
            burst_ms = (time.perf_counter() - t0) * 1000.0
            self.assertLess(burst_ms, 50.0)

            m = bus.metrics()
            self.assertEqual(m["dropped_by_subscriber"][sub_old], 4)
            self.assertEqual(m["dropped_by_subscriber"][sub_new], 4)
            self.assertEqual(m["dropped_events"], 8)
            self.assertLessEqual(m["async_workers"][sub_old]["queue_depth"], 2)
            self.assertLessEqual(m["async_workers"][sub_new]["queue_depth"], 2)

            gate.set()
            self.assertTrue(bus.flush(timeout=2.0))

            # drop_oldest keeps latest [6, 7]; drop_newest keeps earliest [2, 3].
            self.assertEqual(received_oldest, [1, 6, 7])
            self.assertEqual(received_newest, [1, 2, 3])

        self.assertEqual(_eventbus_threads(), [])

    def test_events_since_reconnect_replay_and_last_event_id(self) -> None:
        with ExecutionEventBus(replay_buffer_size=4) as bus:
            for i in range(1, 7):
                etype = ExecutionEventType.TP_HIT if i % 2 == 0 else ExecutionEventType.FILL
                bus.publish(_make_event(f"replay-{i}", event_type=etype))

            # Buffer holds last 4 events: seq 3, 4, 5, 6.
            self.assertEqual([e.seq_id for e in bus.events_since(0)], [3, 4, 5, 6])
            self.assertEqual([e.seq_id for e in bus.events_since(4)], [5, 6])
            self.assertEqual([e.seq_id for e in bus.events_since("4")], [5, 6])
            self.assertEqual([e.seq_id for e in bus.events_since(6)], [])
            self.assertEqual(
                [e.seq_id for e in bus.events_since("2", event_types=[ExecutionEventType.TP_HIT])],
                [4, 6],
            )

            frames = bus.sse_frames_since("4")
            self.assertEqual(len(frames), 2)
            self.assertTrue(frames[0].startswith("id: 5\nevent: FILL\ndata: "))
            self.assertTrue(frames[1].startswith("id: 6\nevent: TP_HIT\ndata: "))

            with self.assertRaises(ValueError):
                bus.events_since(-1)
            with self.assertRaises(ValueError):
                bus.events_since("not-a-number")
            with self.assertRaises(ValueError):
                bus.events_since(True)

    def test_clean_thread_shutdown_and_unsubscribe_zero_leaks(self) -> None:
        baseline = set(_eventbus_threads())
        bus = ExecutionEventBus()
        sub1 = bus.subscribe(lambda ev: None, lane=SubscriberLane.LEDGER_ASYNC)
        sub2 = bus.subscribe(lambda ev: None, lane=SubscriberLane.UI_SSE_ASYNC)
        self.assertEqual(len(set(_eventbus_threads()) - baseline), 2)

        self.assertTrue(bus.unsubscribe(sub1, timeout=1.0))
        self.assertFalse(bus.unsubscribe("non-existent"))
        self.assertEqual(len(set(_eventbus_threads()) - baseline), 1)

        self.assertTrue(bus.close(timeout=1.0))
        self.assertEqual(set(_eventbus_threads()) - baseline, set())
        self.assertTrue(bus.metrics()["closed"])

        with self.assertRaises(RuntimeError):
            bus.publish(_make_event("after-close"))
        with self.assertRaises(RuntimeError):
            bus.subscribe(lambda ev: None, lane=SubscriberLane.LEDGER_ASYNC)
        # sub2 already cleaned up by close()
        self.assertFalse(bus.unsubscribe(sub2))

    def test_concurrent_publishers_preserve_monotonic_seq_and_idempotency(self) -> None:
        delivered_ids: list[str] = []
        delivered_seqs: list[int] = []
        lock = threading.Lock()

        def collector(ev: ExecutionEvent) -> None:
            with lock:
                delivered_ids.append(ev.event_id)
                delivered_seqs.append(ev.seq_id)

        with ExecutionEventBus() as bus:
            bus.subscribe(collector, lane=SubscriberLane.LEDGER_ASYNC)
            barrier = threading.Barrier(4)
            errors: list[Exception] = []

            def worker(worker_idx: int) -> None:
                try:
                    barrier.wait(timeout=2.0)
                    for i in range(25):
                        # Every worker publishes the same 25 shared event_ids concurrently.
                        bus.publish(_make_event(f"shared-evt-{i}"))
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=worker, args=(idx,)) for idx in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5.0)

            self.assertEqual(errors, [])
            self.assertTrue(bus.flush(timeout=3.0))
            m = bus.metrics()
            self.assertEqual(m["published_count"], 25)
            self.assertEqual(m["deduped_count"], 75)
            self.assertEqual(m["last_seq_id"], 25)
            self.assertEqual(len(delivered_ids), 25)
            self.assertEqual(len(set(delivered_ids)), 25)
            self.assertEqual(delivered_seqs, list(range(1, 26)))

        self.assertEqual(_eventbus_threads(), [])


class Mt5PositionDiffEmitterTests(unittest.TestCase):
    def test_full_position_lifecycle_and_zero_duplicates_on_repoll(self) -> None:
        received: list[ExecutionEvent] = []
        with ExecutionEventBus() as bus:
            bus.subscribe(received.append, lane=SubscriberLane.CRITICAL_PROTECTION)
            emitter = Mt5PositionDiffEmitter(bus, broker_id=BROKER_HUGOSWAY_MT5)

            # 1. New FILL from Mt5Position dataclass + dict position (including symbol normalization).
            pos_eur = Mt5Position(
                ticket="1001",
                symbol="EURUSD",
                side=Side.BUY,
                volume_lots=Decimal("1.00"),
                price_open=Decimal("1.08500"),
                stop_loss=Decimal("1.08000"),
                profit=Decimal("0.00"),
                take_profit=Decimal("1.09500"),
            )
            pos_nas_dict = {
                "ticket": "2002",
                "order_id": "ord-nas-2002",
                "symbol": "USTEC",
                "side": "SELL",
                "volume_lots": "0.50",
                "price_open": "20100.00",
                "stop_loss": "20200.00",
                "take_profit": "19900.00",
                "profit": "0.00",
            }
            ev_open = emitter.process_snapshot(
                [pos_eur, pos_nas_dict],
                timestamp_utc="2026-11-20T07:00:00Z",
            )
            self.assertEqual(len(ev_open), 2)
            self.assertEqual([e.event_type for e in ev_open], [ExecutionEventType.FILL, ExecutionEventType.FILL])
            self.assertEqual(ev_open[0].symbol, "EURUSD")
            self.assertEqual(ev_open[1].symbol, "NAS100")

            # 2. Unchanged re-poll MUST emit 0 events.
            ev_noop = emitter.process_snapshot(
                [pos_eur, pos_nas_dict],
                timestamp_utc="2026-11-20T07:00:05Z",
            )
            self.assertEqual(ev_noop, ())

            # 3. Fresh restarted emitter polling the same snapshot onto the same bus MUST dedup (0 new events).
            restarted_emitter = Mt5PositionDiffEmitter(bus, broker_id=BROKER_HUGOSWAY_MT5)
            ev_restart = restarted_emitter.process_snapshot(
                [pos_eur, pos_nas_dict],
                timestamp_utc="2026-11-20T07:00:10Z",
            )
            self.assertEqual(ev_restart, ())
            self.assertEqual(bus.metrics()["deduped_count"], 2)

            # 4. Partial reduce on EURUSD (1.00 -> 0.40 lots) + stop-loss amend to breakeven on EURUSD.
            pos_eur_reduced = Mt5Position(
                ticket="1001",
                symbol="EURUSD",
                side=Side.BUY,
                volume_lots=Decimal("0.40"),
                price_open=Decimal("1.08500"),
                stop_loss=Decimal("1.08500"),
                profit=Decimal("80.00"),
                take_profit=Decimal("1.09500"),
            )
            ev_mod = emitter.process_snapshot(
                [pos_eur_reduced, pos_nas_dict],
                market_prices={"EURUSD": Decimal("1.08900")},
                close_hints={"1001": {"realized_pnl_usd": Decimal("120.00")}},
                timestamp_utc="2026-11-20T07:05:00Z",
            )
            self.assertEqual(
                [e.event_type for e in ev_mod],
                [ExecutionEventType.PARTIAL_FILL, ExecutionEventType.AMEND_STOP],
            )
            partial_ev, amend_ev = ev_mod
            self.assertEqual(partial_ev.quantity_lots, Decimal("0.60"))
            self.assertEqual(partial_ev.price, Decimal("1.08900"))
            self.assertEqual(partial_ev.realized_pnl_usd, Decimal("120.00"))
            self.assertEqual(amend_ev.stop_loss, Decimal("1.08500"))
            self.assertEqual(amend_ev.price, Decimal("1.08500"))

            # 5. TP_HIT on EURUSD (BUY closed at/above take_profit 1.09500) + SL_HIT on NAS100 (SELL closed at/above SL 20200).
            pos_eur_final = Mt5Position(
                ticket="1001",
                symbol="EURUSD",
                side=Side.BUY,
                volume_lots=Decimal("0.40"),
                price_open=Decimal("1.08500"),
                stop_loss=Decimal("1.08500"),
                profit=Decimal("400.00"),
                take_profit=Decimal("1.09500"),
            )
            pos_nas_loss = dict(pos_nas_dict, profit="-250.00")
            # Refresh floating profits without changing volume/SL/TP -> emits 0 events.
            self.assertEqual(
                emitter.process_snapshot([pos_eur_final, pos_nas_loss], timestamp_utc="2026-11-20T07:09:00Z"),
                (),
            )

            ev_closed = emitter.process_snapshot(
                [],
                market_prices={"EURUSD": Decimal("1.09510"), "NAS100": Decimal("20205.00")},
                timestamp_utc="2026-11-20T07:10:00Z",
            )
            self.assertEqual(len(ev_closed), 2)
            self.assertEqual(ev_closed[0].event_type, ExecutionEventType.TP_HIT)
            self.assertEqual(ev_closed[0].position_ticket, "1001")
            self.assertEqual(ev_closed[0].realized_pnl_usd, Decimal("400.00"))
            self.assertEqual(ev_closed[1].event_type, ExecutionEventType.SL_HIT)
            self.assertEqual(ev_closed[1].position_ticket, "2002")
            self.assertEqual(ev_closed[1].realized_pnl_usd, Decimal("-250.00"))

            # 6. Manual close on a new position (price strictly inside SL/TP range).
            pos_gbp = Mt5Position(
                ticket="3003",
                symbol="GBPUSD",
                side=Side.BUY,
                volume_lots=Decimal("0.20"),
                price_open=Decimal("1.27000"),
                stop_loss=Decimal("1.26500"),
                profit=Decimal("35.25"),
                take_profit=Decimal("1.28000"),
            )
            ev_gbp_open = emitter.process_snapshot([pos_gbp], timestamp_utc="2026-11-20T08:00:00Z")
            self.assertEqual(len(ev_gbp_open), 1)
            self.assertEqual(ev_gbp_open[0].event_type, ExecutionEventType.FILL)

            ev_gbp_manual = emitter.process_snapshot(
                [],
                market_prices={"GBPUSD": Decimal("1.27180")},
                timestamp_utc="2026-11-20T08:05:00Z",
            )
            self.assertEqual(len(ev_gbp_manual), 1)
            self.assertEqual(ev_gbp_manual[0].event_type, ExecutionEventType.CLOSE_MANUAL)
            self.assertEqual(ev_gbp_manual[0].price, Decimal("1.27180"))
            self.assertEqual(ev_gbp_manual[0].realized_pnl_usd, Decimal("35.25"))

            # Verify monotonic seq_ids across entire emitted sequence.
            seq_ids = [ev.seq_id for ev in received]
            self.assertEqual(seq_ids, list(range(1, len(received) + 1)))
            self.assertEqual(len(received), 8)

    def test_sell_tp_hit_and_buy_sl_hit_and_explicit_hints(self) -> None:
        with ExecutionEventBus() as bus:
            emitter = Mt5PositionDiffEmitter(bus, broker_id=BROKER_HUGOSWAY_MT5)
            pos_buy = Mt5Position(
                ticket="4001",
                symbol="XAUUSD",
                side=Side.BUY,
                volume_lots=Decimal("0.10"),
                price_open=Decimal("2650.00"),
                stop_loss=Decimal("2640.00"),
                profit=Decimal("-100.00"),
                take_profit=Decimal("2680.00"),
            )
            pos_sell = Mt5Position(
                ticket="4002",
                symbol="USDJPY",
                side=Side.SELL,
                volume_lots=Decimal("0.30"),
                price_open=Decimal("154.000"),
                stop_loss=Decimal("154.500"),
                profit=Decimal("195.00"),
                take_profit=Decimal("153.000"),
            )
            emitter.process_snapshot([pos_buy, pos_sell], timestamp_utc="2026-11-20T09:00:00Z")

            closed = emitter.process_snapshot(
                [],
                market_prices={"XAUUSD": Decimal("2639.50"), "USDJPY": Decimal("152.990")},
                timestamp_utc="2026-11-20T09:10:00Z",
            )
            self.assertEqual([e.event_type for e in closed], [ExecutionEventType.SL_HIT, ExecutionEventType.TP_HIT])

            # Explicit close_hint overrides price-based classification when broker reports exact reason.
            pos_hint = Mt5Position(
                ticket="4003",
                symbol="EURUSD",
                side=Side.BUY,
                volume_lots=Decimal("0.10"),
                price_open=Decimal("1.08500"),
                stop_loss=Decimal("1.08000"),
                profit=Decimal("10.00"),
                take_profit=Decimal("1.09500"),
            )
            emitter.process_snapshot([pos_hint], timestamp_utc="2026-11-20T09:20:00Z")
            hinted = emitter.process_snapshot(
                [],
                close_hints={"4003": {"reason": "SL_HIT", "close_price": "1.08000", "realized_pnl_usd": "-50.00"}},
                timestamp_utc="2026-11-20T09:25:00Z",
            )
            self.assertEqual(len(hinted), 1)
            self.assertEqual(hinted[0].event_type, ExecutionEventType.SL_HIT)
            self.assertEqual(hinted[0].price, Decimal("1.08000"))
            self.assertEqual(hinted[0].realized_pnl_usd, Decimal("-50.00"))


if __name__ == "__main__":
    unittest.main()
