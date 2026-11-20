"""Event-driven broker fill and close push stream for CAS Forex Revamp (Phase 8).

Clear Street real-time trade/event streaming architecture adapted to CAS Forex:

- Immutable, deterministically hashed :class:`ExecutionEvent` records with exact
  ``Decimal`` serialization and injection-safe Server-Sent Events (SSE) framing.
- Priority and lane-isolated :class:`ExecutionEventBus` separating inline
  ``CRITICAL_PROTECTION`` handlers from bounded, per-subscriber worker-queue
  ``LEDGER_ASYNC`` and ``UI_SSE_ASYNC`` lanes so slow or failing downstream
  subscribers never stall or abort ``publish()`` or protective handlers.
- Strict idempotency deduplication by ``event_id``, monotonic ``seq_id``
  assignment, bounded ``events_since(seq_id)`` reconnect replay buffer, and
  isolated per-lane / per-subscriber error and drop metrics.
- Stateful :class:`Mt5PositionDiffEmitter` converting successive broker position
  snapshots (``Mt5Position`` or mapping objects) into deterministic
  ``FILL``, ``PARTIAL_FILL``, ``SL_HIT``, ``TP_HIT``, ``AMEND_STOP``, and
  ``CLOSE_MANUAL`` events without duplicate re-emission on unchanged polls.

Safety invariants:
- Importing this module has zero network, disk, or thread side effects.
- Worker threads are daemonized, explicitly joined via :meth:`shutdown` /
  :meth:`close` and context-manager exit, and never hold bus locks during
  subscriber callbacks.
- All monetary and quantity fields use exact finite :class:`decimal.Decimal`
  values; floats and booleans are rejected.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from hashlib import sha256
import json
import logging
import re
import threading
import time
from typing import Any, Literal

from cas_forex_revamp.contracts import Side
from .mt5_broker_bridge import BROKER_HUGOSWAY_MT5, normalize_market_symbol

__all__ = [
    "DEFAULT_DEDUP_CACHE_SIZE",
    "DEFAULT_QUEUE_MAXSIZE",
    "DEFAULT_REPLAY_BUFFER_SIZE",
    "DropPolicy",
    "ExecutionEvent",
    "ExecutionEventBus",
    "ExecutionEventType",
    "Mt5PositionDiffEmitter",
    "SubscriberLane",
]

logger = logging.getLogger(__name__)

DEFAULT_QUEUE_MAXSIZE = 1024
DEFAULT_REPLAY_BUFFER_SIZE = 10_000
DEFAULT_DEDUP_CACHE_SIZE = 100_000

DropPolicy = Literal["drop_oldest", "drop_newest"]

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f\u2028\u2029]+")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ISO_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)$"
)


class ExecutionEventType(StrEnum):
    """Canonical broker execution and position lifecycle event types."""

    FILL = "FILL"
    PARTIAL_FILL = "PARTIAL_FILL"
    SL_HIT = "SL_HIT"
    TP_HIT = "TP_HIT"
    CANCELLED = "CANCELLED"
    AMEND_STOP = "AMEND_STOP"
    REJECTED = "REJECTED"
    CLOSE_MANUAL = "CLOSE_MANUAL"


class SubscriberLane(StrEnum):
    """Execution lanes isolating critical protection from async consumers."""

    CRITICAL_PROTECTION = "CRITICAL_PROTECTION"
    LEDGER_ASYNC = "LEDGER_ASYNC"
    UI_SSE_ASYNC = "UI_SSE_ASYNC"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _validate_nonempty_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _validate_decimal(value: Any, field: str, *, allow_none: bool = False) -> Decimal | None:
    if value is None:
        if allow_none:
            return None
        raise TypeError(f"{field} must be a finite Decimal, not None")
    if isinstance(value, bool) or isinstance(value, float):
        raise TypeError(f"{field} must be a finite Decimal, never float or bool")
    if not isinstance(value, Decimal):
        raise TypeError(f"{field} must be a finite Decimal, got {type(value).__name__}")
    if not value.is_finite():
        raise ValueError(f"{field} must be a finite Decimal")
    return value


def _coerce_snapshot_decimal(value: Any, field: str, *, allow_none: bool = False) -> Decimal | None:
    """Parse Decimal or exact decimal string/int from broker snapshots (rejects float/bool)."""
    if value is None:
        if allow_none:
            return None
        raise TypeError(f"{field} is required")
    if isinstance(value, bool) or isinstance(value, float):
        raise TypeError(f"{field} must be Decimal, int, or decimal string, never float or bool")
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError(f"{field} must be finite")
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            if allow_none:
                return None
            raise ValueError(f"{field} must not be empty")
        try:
            parsed = Decimal(stripped)
        except InvalidOperation as exc:
            raise ValueError(f"{field} is not a valid decimal string") from exc
        if not parsed.is_finite():
            raise ValueError(f"{field} must be finite")
        return parsed
    raise TypeError(f"{field} must be Decimal, int, or str, got {type(value).__name__}")


def _decimal_to_canonical_str(value: Decimal) -> str:
    if value == 0:
        return "0"
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _normalize_side(value: Any) -> str:
    if isinstance(value, Side):
        return value.value
    if not isinstance(value, str) or not value.strip():
        raise ValueError("side must be a non-empty Side or string")
    upper = value.strip().upper()
    if upper in ("BUY", "LONG"):
        return Side.BUY.value
    if upper in ("SELL", "SHORT"):
        return Side.SELL.value
    return upper


def _normalize_timestamp_utc(value: Any) -> str:
    if value is None or value == "":
        return _utc_now_iso()
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp_utc datetime must be timezone-aware UTC")
        if value.utcoffset().total_seconds() != 0:
            raise ValueError("timestamp_utc datetime must be UTC")
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if not isinstance(value, str):
        raise TypeError("timestamp_utc must be an ISO-8601 UTC string")
    stripped = value.strip()
    if not _ISO_UTC_RE.fullmatch(stripped):
        raise ValueError("timestamp_utc must be a valid ISO-8601 UTC timestamp")
    if stripped.endswith("+00:00"):
        return stripped[:-6] + "Z"
    return stripped


def _sanitize_sse_header_value(raw: str) -> str:
    """Strip CR/LF/NUL/control characters to prevent SSE frame injection."""
    return _CONTROL_CHARS_RE.sub("", raw)


@dataclass(frozen=True, slots=True)
class ExecutionEvent:
    """Immutable broker execution event with canonical SHA-256 digest and SSE framing."""

    event_id: str
    event_type: ExecutionEventType
    broker_id: str
    symbol: str
    order_id: str
    position_ticket: str
    side: str
    quantity_lots: Decimal
    price: Decimal
    realized_pnl_usd: Decimal = Decimal("0")
    timestamp_utc: str = ""
    seq_id: int = 0
    payload_sha256: str = ""
    stop_loss: Decimal | None = None
    take_profit: Decimal | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        _validate_nonempty_str(self.event_id, "event_id")
        if isinstance(self.event_type, str) and not isinstance(self.event_type, ExecutionEventType):
            object.__setattr__(self, "event_type", ExecutionEventType(self.event_type))
        elif not isinstance(self.event_type, ExecutionEventType):
            raise TypeError("event_type must be ExecutionEventType")
        _validate_nonempty_str(self.broker_id, "broker_id")
        _validate_nonempty_str(self.symbol, "symbol")
        if not isinstance(self.order_id, str):
            raise TypeError("order_id must be a string")
        if not isinstance(self.position_ticket, str):
            raise TypeError("position_ticket must be a string")
        object.__setattr__(self, "side", _normalize_side(self.side))
        _validate_decimal(self.quantity_lots, "quantity_lots")
        if self.quantity_lots < 0:
            raise ValueError("quantity_lots must be >= 0")
        _validate_decimal(self.price, "price")
        if self.price < 0:
            raise ValueError("price must be >= 0")
        _validate_decimal(self.realized_pnl_usd, "realized_pnl_usd")
        _validate_decimal(self.stop_loss, "stop_loss", allow_none=True)
        _validate_decimal(self.take_profit, "take_profit", allow_none=True)
        if not isinstance(self.reason, str):
            raise TypeError("reason must be a string")
        if type(self.seq_id) is not int or self.seq_id < 0:
            raise ValueError("seq_id must be a non-negative integer")
        normalized_ts = _normalize_timestamp_utc(self.timestamp_utc)
        object.__setattr__(self, "timestamp_utc", normalized_ts)

        expected_sha = self.compute_payload_sha256()
        if not self.payload_sha256:
            object.__setattr__(self, "payload_sha256", expected_sha)
        else:
            if not isinstance(self.payload_sha256, str) or not _SHA256_RE.fullmatch(self.payload_sha256):
                raise ValueError("payload_sha256 must be a 64-character lowercase hex digest")
            if self.payload_sha256 != expected_sha:
                raise ValueError("payload_sha256 does not match canonical event payload")

    def canonical_payload(self) -> dict[str, Any]:
        """Return deterministic canonical payload dictionary with exact Decimal strings."""
        return {
            "broker_id": self.broker_id,
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "order_id": self.order_id,
            "position_ticket": self.position_ticket,
            "price": _decimal_to_canonical_str(self.price),
            "quantity_lots": _decimal_to_canonical_str(self.quantity_lots),
            "realized_pnl_usd": _decimal_to_canonical_str(self.realized_pnl_usd),
            "reason": self.reason,
            "side": self.side,
            "stop_loss": None if self.stop_loss is None else _decimal_to_canonical_str(self.stop_loss),
            "symbol": self.symbol,
            "take_profit": None if self.take_profit is None else _decimal_to_canonical_str(self.take_profit),
            "timestamp_utc": self.timestamp_utc,
        }

    def compute_payload_sha256(self) -> str:
        """Compute deterministic SHA-256 hex digest over canonical payload fields."""
        encoded = json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
            ensure_ascii=True,
        ).encode("utf-8")
        return sha256(encoded).hexdigest()

    def verify_payload_sha256(self) -> bool:
        """Return True iff stored payload_sha256 matches the recomputed canonical digest."""
        return self.payload_sha256 == self.compute_payload_sha256()

    def with_seq_id(self, seq_id: int) -> ExecutionEvent:
        """Return a new immutable copy stamped with the bus-assigned monotonic seq_id."""
        if type(seq_id) is not int or seq_id < 1:
            raise ValueError("assigned seq_id must be an integer >= 1")
        return replace(self, seq_id=seq_id)

    def to_dict(self) -> dict[str, Any]:
        """Serialize event to a JSON-safe dict with exact Decimal strings."""
        payload = self.canonical_payload()
        payload["seq_id"] = self.seq_id
        payload["payload_sha256"] = self.payload_sha256
        return payload

    def to_sse_frame(self) -> str:
        """Render a single sanitized Server-Sent Events (SSE) frame.

        Control characters (CR, LF, NUL, U+2028, U+2029) are stripped from header
        fields and JSON-escaped inside ``data:`` so untrusted broker text can
        never inject forged SSE lines or split frames.
        """
        raw_id = str(self.seq_id) if self.seq_id > 0 else self.event_id
        safe_id = _sanitize_sse_header_value(raw_id) or "0"
        safe_event = _sanitize_sse_header_value(self.event_type.value)
        safe_data = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
            ensure_ascii=True,
        )
        return f"id: {safe_id}\nevent: {safe_event}\ndata: {safe_data}\n\n"


@dataclass(slots=True)
class _CriticalSubscriber:
    subscriber_id: str
    name: str
    callback: Callable[[ExecutionEvent], Any]
    event_types: frozenset[ExecutionEventType] | None


class _AsyncSubscriberWorker:
    """Dedicated bounded-queue daemon worker for a single async subscriber."""

    def __init__(
        self,
        *,
        subscriber_id: str,
        name: str,
        lane: SubscriberLane,
        callback: Callable[[ExecutionEvent], Any],
        event_types: frozenset[ExecutionEventType] | None,
        maxsize: int,
        drop_policy: DropPolicy,
        on_error: Callable[[str, SubscriberLane, ExecutionEvent, Exception], None],
    ) -> None:
        if type(maxsize) is not int or maxsize < 1:
            raise ValueError("queue_maxsize must be an integer >= 1")
        if drop_policy not in ("drop_oldest", "drop_newest"):
            raise ValueError("drop_policy must be 'drop_oldest' or 'drop_newest'")

        self.subscriber_id = subscriber_id
        self.name = name
        self.lane = lane
        self.event_types = event_types
        self._callback = callback
        self._maxsize = maxsize
        self._drop_policy = drop_policy
        self._on_error = on_error

        self._cond = threading.Condition(threading.Lock())
        self._queue: deque[ExecutionEvent] = deque()
        self._in_flight = 0
        self._closed = False
        self._stop_immediately = False

        self.delivered_count = 0
        self.dropped_count = 0
        self.error_count = 0
        self.last_error: str | None = None

        self._thread = threading.Thread(
            target=self._run,
            name=f"cas-eventbus-{lane.value.lower()}-{subscriber_id}",
            daemon=True,
        )
        self._thread.start()

    def matches(self, event: ExecutionEvent) -> bool:
        return self.event_types is None or event.event_type in self.event_types

    def enqueue(self, event: ExecutionEvent) -> bool:
        """Non-blocking bounded enqueue. Returns True if an event was dropped due to backpressure."""
        with self._cond:
            if self._closed:
                return False
            dropped = False
            if len(self._queue) >= self._maxsize:
                if self._drop_policy == "drop_oldest":
                    self._queue.popleft()
                    self._queue.append(event)
                self.dropped_count += 1
                dropped = True
            else:
                self._queue.append(event)
            self._cond.notify_all()
            return dropped

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait up to timeout seconds for queued and in-flight events to finish."""
        if timeout < 0:
            raise ValueError("timeout must be >= 0")
        deadline = time.monotonic() + timeout
        with self._cond:
            while self._queue or self._in_flight > 0:
                if self._stop_immediately and self._in_flight == 0:
                    return False
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._cond.wait(timeout=remaining)
            return True

    def stop(self, timeout: float = 2.0, *, drain: bool = False) -> bool:
        """Signal worker thread to exit and join it within timeout seconds."""
        if timeout < 0:
            raise ValueError("timeout must be >= 0")
        deadline = time.monotonic() + timeout
        with self._cond:
            self._closed = True
            if not drain:
                self._stop_immediately = True
            self._cond.notify_all()

        remaining = max(0.0, deadline - time.monotonic())
        if threading.current_thread() is not self._thread:
            self._thread.join(timeout=remaining)
            if self._thread.is_alive() and drain:
                with self._cond:
                    self._stop_immediately = True
                    self._cond.notify_all()
                self._thread.join(timeout=0.5)
        return not self._thread.is_alive()

    def snapshot_stats(self) -> dict[str, Any]:
        with self._cond:
            return {
                "subscriber_id": self.subscriber_id,
                "name": self.name,
                "lane": self.lane.value,
                "queue_depth": len(self._queue),
                "queue_maxsize": self._maxsize,
                "in_flight": self._in_flight,
                "delivered_count": self.delivered_count,
                "dropped_count": self.dropped_count,
                "error_count": self.error_count,
                "last_error": self.last_error,
                "alive": self._thread.is_alive(),
            }

    def _run(self) -> None:
        while True:
            with self._cond:
                while not self._queue and not self._closed:
                    self._cond.wait()
                if self._stop_immediately:
                    break
                if not self._queue and self._closed:
                    break
                event = self._queue.popleft()
                self._in_flight += 1

            try:
                self._callback(event)
            except Exception as exc:
                with self._cond:
                    self.error_count += 1
                    self.last_error = f"{type(exc).__name__}: {exc}"
                self._on_error(self.subscriber_id, self.lane, event, exc)
            else:
                with self._cond:
                    self.delivered_count += 1
            finally:
                with self._cond:
                    self._in_flight -= 1
                    if not self._queue and self._in_flight == 0:
                        self._cond.notify_all()


class ExecutionEventBus:
    """Lane-isolated, idempotent real-time execution event bus with SSE replay."""

    def __init__(
        self,
        *,
        default_queue_maxsize: int = DEFAULT_QUEUE_MAXSIZE,
        default_drop_policy: DropPolicy = "drop_oldest",
        replay_buffer_size: int = DEFAULT_REPLAY_BUFFER_SIZE,
        dedup_cache_size: int = DEFAULT_DEDUP_CACHE_SIZE,
    ) -> None:
        if type(default_queue_maxsize) is not int or default_queue_maxsize < 1:
            raise ValueError("default_queue_maxsize must be an integer >= 1")
        if default_drop_policy not in ("drop_oldest", "drop_newest"):
            raise ValueError("default_drop_policy must be 'drop_oldest' or 'drop_newest'")
        if type(replay_buffer_size) is not int or replay_buffer_size < 1:
            raise ValueError("replay_buffer_size must be an integer >= 1")
        if type(dedup_cache_size) is not int or dedup_cache_size < 1:
            raise ValueError("dedup_cache_size must be an integer >= 1")

        self._default_queue_maxsize = default_queue_maxsize
        self._default_drop_policy: DropPolicy = default_drop_policy
        self._dedup_cache_size = dedup_cache_size

        self._lock = threading.RLock()
        self._closed = False
        self._seq_id = 0
        self._next_sub_num = 0

        self._seen_events: OrderedDict[str, ExecutionEvent] = OrderedDict()
        self._replay_buffer: deque[ExecutionEvent] = deque(maxlen=replay_buffer_size)

        self._critical_subs: dict[str, _CriticalSubscriber] = {}
        self._async_workers: dict[str, _AsyncSubscriberWorker] = {}

        self._published_count = 0
        self._deduped_count = 0
        self._dropped_events = 0
        self._subscriber_errors = 0
        self._errors_by_lane: dict[str, int] = {lane.value: 0 for lane in SubscriberLane}
        self._errors_by_subscriber: dict[str, int] = {}

    def __enter__(self) -> ExecutionEventBus:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.shutdown(timeout=2.0, drain=False)

    def subscribe(
        self,
        callback: Callable[[ExecutionEvent], Any],
        *,
        lane: SubscriberLane | str = SubscriberLane.LEDGER_ASYNC,
        name: str | None = None,
        event_types: Iterable[ExecutionEventType] | None = None,
        queue_maxsize: int | None = None,
        drop_policy: DropPolicy | None = None,
    ) -> str:
        """Register a subscriber on the requested isolation lane and return its subscriber_id."""
        if not callable(callback):
            raise TypeError("callback must be callable")
        resolved_lane = lane if isinstance(lane, SubscriberLane) else SubscriberLane(lane)
        resolved_types: frozenset[ExecutionEventType] | None = None
        if event_types is not None:
            resolved_types = frozenset(
                et if isinstance(et, ExecutionEventType) else ExecutionEventType(et)
                for et in event_types
            )

        with self._lock:
            if self._closed:
                raise RuntimeError("cannot subscribe to a closed ExecutionEventBus")
            self._next_sub_num += 1
            sub_id = f"sub-{self._next_sub_num}"
            sub_name = name if name is not None else sub_id
            self._errors_by_subscriber.setdefault(sub_id, 0)

            if resolved_lane is SubscriberLane.CRITICAL_PROTECTION:
                self._critical_subs[sub_id] = _CriticalSubscriber(
                    subscriber_id=sub_id,
                    name=sub_name,
                    callback=callback,
                    event_types=resolved_types,
                )
            else:
                worker = _AsyncSubscriberWorker(
                    subscriber_id=sub_id,
                    name=sub_name,
                    lane=resolved_lane,
                    callback=callback,
                    event_types=resolved_types,
                    maxsize=self._default_queue_maxsize if queue_maxsize is None else queue_maxsize,
                    drop_policy=self._default_drop_policy if drop_policy is None else drop_policy,
                    on_error=self._record_subscriber_error,
                )
                self._async_workers[sub_id] = worker
            return sub_id

    def unsubscribe(self, subscriber_id: str, *, timeout: float = 2.0, drain: bool = False) -> bool:
        """Remove a subscriber and cleanly stop its worker thread if async."""
        worker: _AsyncSubscriberWorker | None = None
        with self._lock:
            if subscriber_id in self._critical_subs:
                del self._critical_subs[subscriber_id]
                return True
            worker = self._async_workers.pop(subscriber_id, None)
        if worker is None:
            return False
        worker.stop(timeout=timeout, drain=drain)
        return True

    def was_seen(self, event_id: str) -> bool:
        """Return True if event_id has already been published to this bus."""
        with self._lock:
            return event_id in self._seen_events

    def publish_idempotent(self, event: ExecutionEvent) -> tuple[ExecutionEvent, bool]:
        """Publish an event with strict idempotency dedup by event_id.

        Returns ``(stamped_event, is_new)``. Duplicate ``event_id`` submissions
        return the original stamped event with ``is_new=False`` and never invoke
        any subscriber callbacks.
        """
        if not isinstance(event, ExecutionEvent):
            raise TypeError("event must be an ExecutionEvent")

        with self._lock:
            if self._closed:
                raise RuntimeError("ExecutionEventBus is closed")
            existing = self._seen_events.get(event.event_id)
            if existing is not None:
                self._deduped_count += 1
                return existing, False

            self._seq_id += 1
            stamped = event.with_seq_id(self._seq_id)
            self._seen_events[stamped.event_id] = stamped
            if len(self._seen_events) > self._dedup_cache_size:
                self._seen_events.popitem(last=False)
            self._replay_buffer.append(stamped)
            self._published_count += 1

            critical_subs = tuple(self._critical_subs.values())
            async_workers = tuple(self._async_workers.values())

        # Execute CRITICAL_PROTECTION lane inline without holding bus lock.
        for sub in critical_subs:
            if sub.event_types is not None and stamped.event_type not in sub.event_types:
                continue
            try:
                sub.callback(stamped)
            except Exception as exc:
                self._record_subscriber_error(
                    sub.subscriber_id,
                    SubscriberLane.CRITICAL_PROTECTION,
                    stamped,
                    exc,
                )

        # Non-blocking enqueue into per-subscriber async lanes.
        dropped_here = 0
        for worker in async_workers:
            if not worker.matches(stamped):
                continue
            if worker.enqueue(stamped):
                dropped_here += 1

        if dropped_here:
            with self._lock:
                self._dropped_events += dropped_here

        return stamped, True

    def publish(self, event: ExecutionEvent) -> ExecutionEvent:
        """Publish an event onto all matching lanes and return the stamped ExecutionEvent."""
        stamped, _ = self.publish_idempotent(event)
        return stamped

    def events_since(
        self,
        seq_id: int | str,
        *,
        event_types: Iterable[ExecutionEventType] | None = None,
    ) -> tuple[ExecutionEvent, ...]:
        """Return buffered events with seq_id strictly greater than the given cursor."""
        cursor = _parse_seq_cursor(seq_id)
        type_filter: frozenset[ExecutionEventType] | None = None
        if event_types is not None:
            type_filter = frozenset(
                et if isinstance(et, ExecutionEventType) else ExecutionEventType(et)
                for et in event_types
            )
        with self._lock:
            return tuple(
                ev
                for ev in self._replay_buffer
                if ev.seq_id > cursor and (type_filter is None or ev.event_type in type_filter)
            )

    def sse_frames_since(
        self,
        seq_id: int | str,
        *,
        event_types: Iterable[ExecutionEventType] | None = None,
    ) -> tuple[str, ...]:
        """Return sanitized SSE frames for all buffered events after seq_id (Last-Event-ID)."""
        return tuple(ev.to_sse_frame() for ev in self.events_since(seq_id, event_types=event_types))

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait up to timeout seconds for all async subscribers to drain pending events."""
        if timeout < 0:
            raise ValueError("timeout must be >= 0")
        deadline = time.monotonic() + timeout
        with self._lock:
            workers = tuple(self._async_workers.values())
        all_flushed = True
        for worker in workers:
            remaining = max(0.0, deadline - time.monotonic())
            if not worker.flush(timeout=remaining):
                all_flushed = False
        return all_flushed

    def shutdown(self, timeout: float = 2.0, *, drain: bool = False) -> bool:
        """Close the bus and cleanly join all async worker threads within timeout."""
        if timeout < 0:
            raise ValueError("timeout must be >= 0")
        deadline = time.monotonic() + timeout
        with self._lock:
            self._closed = True
            workers = tuple(self._async_workers.values())
            self._async_workers.clear()
            self._critical_subs.clear()

        for worker in workers:
            with worker._cond:
                worker._closed = True
                if not drain:
                    worker._stop_immediately = True
                worker._cond.notify_all()

        all_stopped = True
        for worker in workers:
            remaining = max(0.0, deadline - time.monotonic())
            if not worker.stop(timeout=remaining, drain=drain):
                all_stopped = False
        return all_stopped

    def close(self, timeout: float = 2.0, *, drain: bool = False) -> bool:
        """Alias for :meth:`shutdown`."""
        return self.shutdown(timeout=timeout, drain=drain)

    def metrics(self) -> dict[str, Any]:
        """Return a thread-safe snapshot of bus delivery, dedup, drop, and error metrics."""
        with self._lock:
            workers = tuple(self._async_workers.values())
            worker_stats = {w.subscriber_id: w.snapshot_stats() for w in workers}
            return {
                "published_count": self._published_count,
                "deduped_count": self._deduped_count,
                "dropped_events": self._dropped_events,
                "subscriber_errors": self._subscriber_errors,
                "last_seq_id": self._seq_id,
                "replay_buffer_len": len(self._replay_buffer),
                "replay_buffer_maxlen": self._replay_buffer.maxlen,
                "active_subscribers": len(self._critical_subs) + len(workers),
                "subscriber_errors_by_lane": dict(self._errors_by_lane),
                "subscriber_errors_by_id": dict(self._errors_by_subscriber),
                "dropped_by_subscriber": {
                    sid: stats["dropped_count"] for sid, stats in worker_stats.items()
                },
                "async_workers": worker_stats,
                "closed": self._closed,
            }

    def _record_subscriber_error(
        self,
        subscriber_id: str,
        lane: SubscriberLane,
        event: ExecutionEvent,
        exc: Exception,
    ) -> None:
        with self._lock:
            self._subscriber_errors += 1
            self._errors_by_lane[lane.value] = self._errors_by_lane.get(lane.value, 0) + 1
            self._errors_by_subscriber[subscriber_id] = (
                self._errors_by_subscriber.get(subscriber_id, 0) + 1
            )
        logger.warning(
            "ExecutionEventBus subscriber %s (%s) failed on seq_id=%s event_id=%s: %s: %s",
            subscriber_id,
            lane.value,
            event.seq_id,
            event.event_id,
            type(exc).__name__,
            exc,
        )


def _parse_seq_cursor(seq_id: int | str) -> int:
    if isinstance(seq_id, bool):
        raise ValueError("seq_id cursor must be an integer >= 0")
    if isinstance(seq_id, int):
        if seq_id < 0:
            raise ValueError("seq_id cursor must be >= 0")
        return seq_id
    if isinstance(seq_id, str):
        stripped = seq_id.strip()
        if not stripped.isdigit():
            raise ValueError("seq_id cursor string must be a non-negative integer")
        return int(stripped)
    raise TypeError("seq_id cursor must be an int or non-negative integer string")


@dataclass(frozen=True, slots=True)
class _NormalizedPosition:
    ticket: str
    order_id: str
    symbol: str
    side: str
    volume_lots: Decimal
    price_open: Decimal
    stop_loss: Decimal | None
    take_profit: Decimal | None
    profit: Decimal
    price_current: Decimal | None = None
    realized_pnl_usd: Decimal | None = None


def _extract_attr_or_key(obj: Any, *names: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        for name in names:
            if name in obj:
                return obj[name]
        return default
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return default


def _normalize_position_record(raw: Any) -> _NormalizedPosition:
    ticket_val = _extract_attr_or_key(raw, "ticket", "position_ticket")
    if ticket_val is None or not str(ticket_val).strip():
        raise ValueError("position snapshot requires non-empty ticket/position_ticket")
    ticket = str(ticket_val).strip()

    order_val = _extract_attr_or_key(raw, "order_id", default=None)
    order_id = str(order_val).strip() if order_val is not None and str(order_val).strip() else f"ord-{ticket}"

    symbol_raw = _extract_attr_or_key(raw, "symbol")
    if not isinstance(symbol_raw, str) or not symbol_raw.strip():
        raise ValueError(f"position {ticket} requires non-empty symbol")
    try:
        symbol = normalize_market_symbol(symbol_raw)
    except Exception:
        symbol = symbol_raw.strip().upper()

    side_raw = _extract_attr_or_key(raw, "side")
    side = _normalize_side(side_raw)

    volume_lots = _coerce_snapshot_decimal(
        _extract_attr_or_key(raw, "volume_lots", "quantity_lots"),
        "volume_lots",
    )
    if volume_lots is None or volume_lots <= 0:
        raise ValueError(f"open position {ticket} must have positive volume_lots")

    price_open = _coerce_snapshot_decimal(
        _extract_attr_or_key(raw, "price_open", "price"),
        "price_open",
    )
    if price_open is None or price_open < 0:
        raise ValueError(f"position {ticket} price_open must be >= 0")

    stop_loss = _coerce_snapshot_decimal(
        _extract_attr_or_key(raw, "stop_loss", default=None),
        "stop_loss",
        allow_none=True,
    )
    take_profit = _coerce_snapshot_decimal(
        _extract_attr_or_key(raw, "take_profit", default=None),
        "take_profit",
        allow_none=True,
    )
    profit = _coerce_snapshot_decimal(
        _extract_attr_or_key(raw, "profit", default=Decimal("0")),
        "profit",
    )
    if profit is None:
        raise ValueError(f"position {ticket} profit must not be None")

    price_current = _coerce_snapshot_decimal(
        _extract_attr_or_key(raw, "price_current", "close_price", default=None),
        "price_current",
        allow_none=True,
    )
    realized_pnl_usd = _coerce_snapshot_decimal(
        _extract_attr_or_key(raw, "realized_pnl_usd", default=None),
        "realized_pnl_usd",
        allow_none=True,
    )

    return _NormalizedPosition(
        ticket=ticket,
        order_id=order_id,
        symbol=symbol,
        side=side,
        volume_lots=volume_lots,
        price_open=price_open,
        stop_loss=stop_loss,
        take_profit=take_profit,
        profit=profit,
        price_current=price_current,
        realized_pnl_usd=realized_pnl_usd,
    )


def _opt_decimal_key(value: Decimal | None) -> str:
    return "NONE" if value is None else _decimal_to_canonical_str(value)


class Mt5PositionDiffEmitter:
    """Stateful diff engine emitting deterministic ExecutionEvents from MT5 snapshots."""

    def __init__(
        self,
        bus: ExecutionEventBus,
        *,
        broker_id: str = BROKER_HUGOSWAY_MT5,
        price_tolerance: Decimal = Decimal("0.0005"),
    ) -> None:
        if not isinstance(bus, ExecutionEventBus):
            raise TypeError("bus must be an ExecutionEventBus")
        _validate_nonempty_str(broker_id, "broker_id")
        _validate_decimal(price_tolerance, "price_tolerance")
        if price_tolerance < 0:
            raise ValueError("price_tolerance must be >= 0")

        self._bus = bus
        self._broker_id = broker_id
        self._price_tolerance = price_tolerance
        self._lock = threading.Lock()
        self._positions: dict[str, _NormalizedPosition] = {}

    @property
    def broker_id(self) -> str:
        return self._broker_id

    def tracked_positions(self) -> dict[str, dict[str, Any]]:
        """Return a read-only copy of currently tracked broker positions."""
        with self._lock:
            return {
                ticket: {
                    "ticket": pos.ticket,
                    "order_id": pos.order_id,
                    "symbol": pos.symbol,
                    "side": pos.side,
                    "volume_lots": pos.volume_lots,
                    "price_open": pos.price_open,
                    "stop_loss": pos.stop_loss,
                    "take_profit": pos.take_profit,
                    "profit": pos.profit,
                }
                for ticket, pos in self._positions.items()
            }

    def process_snapshot(
        self,
        positions: Iterable[Any],
        *,
        market_prices: Mapping[str, Decimal | str | int] | None = None,
        close_hints: Mapping[str, Mapping[str, Any]] | None = None,
        timestamp_utc: str | None = None,
    ) -> tuple[ExecutionEvent, ...]:
        """Diff current broker positions against prior state and publish exact events.

        Returns a tuple of newly published (non-deduped) stamped ExecutionEvents.
        Identical repeated snapshots emit 0 events.
        """
        event_ts = _normalize_timestamp_utc(timestamp_utc)
        normalized_prices: dict[str, Decimal] = {}
        if market_prices is not None:
            for raw_sym, raw_px in market_prices.items():
                px = _coerce_snapshot_decimal(raw_px, f"market_prices[{raw_sym}]")
                if px is None:
                    raise ValueError(f"market_prices[{raw_sym}] must not be None")
                normalized_prices[raw_sym] = px
                try:
                    normalized_prices[normalize_market_symbol(raw_sym)] = px
                except Exception:
                    normalized_prices[raw_sym.strip().upper()] = px

        current_map: dict[str, _NormalizedPosition] = {}
        for item in positions:
            rec = _normalize_position_record(item)
            if rec.ticket in current_map:
                raise ValueError(f"duplicate position ticket in snapshot: {rec.ticket}")
            current_map[rec.ticket] = rec

        pending_events: list[ExecutionEvent] = []
        with self._lock:
            prev_map = self._positions

            for ticket in sorted(current_map):
                curr = current_map[ticket]
                prev = prev_map.get(ticket)
                if prev is None:
                    event_id = (
                        f"mt5:{self._broker_id}:FILL:{curr.ticket}:{curr.symbol}:"
                        f"{curr.side}:{_decimal_to_canonical_str(curr.volume_lots)}:"
                        f"{_decimal_to_canonical_str(curr.price_open)}"
                    )
                    pending_events.append(
                        ExecutionEvent(
                            event_id=event_id,
                            event_type=ExecutionEventType.FILL,
                            broker_id=self._broker_id,
                            symbol=curr.symbol,
                            order_id=curr.order_id,
                            position_ticket=curr.ticket,
                            side=curr.side,
                            quantity_lots=curr.volume_lots,
                            price=curr.price_open,
                            realized_pnl_usd=Decimal("0"),
                            timestamp_utc=event_ts,
                            stop_loss=curr.stop_loss,
                            take_profit=curr.take_profit,
                            reason="position_opened",
                        )
                    )
                    continue

                if curr.volume_lots != prev.volume_lots:
                    delta_lots = (prev.volume_lots - curr.volume_lots).copy_abs()
                    hint = close_hints.get(ticket, {}) if close_hints else {}
                    hint_px = _coerce_snapshot_decimal(
                        hint.get("close_price", hint.get("price")),
                        "hint_price",
                        allow_none=True,
                    )
                    fill_price = (
                        hint_px
                        if hint_px is not None
                        else (
                            curr.price_current
                            if curr.price_current is not None
                            else normalized_prices.get(curr.symbol, curr.price_open)
                        )
                    )
                    hint_pnl = _coerce_snapshot_decimal(
                        hint.get("realized_pnl_usd"),
                        "realized_pnl_usd",
                        allow_none=True,
                    )
                    if hint_pnl is not None:
                        realized_pnl = hint_pnl
                    elif curr.realized_pnl_usd is not None:
                        realized_pnl = curr.realized_pnl_usd
                    elif curr.volume_lots < prev.volume_lots:
                        realized_pnl = prev.profit - curr.profit
                    else:
                        realized_pnl = Decimal("0")

                    action_note = (
                        "partial_reduce" if curr.volume_lots < prev.volume_lots else "partial_add"
                    )
                    event_id = (
                        f"mt5:{self._broker_id}:PARTIAL_FILL:{curr.ticket}:"
                        f"{_decimal_to_canonical_str(prev.volume_lots)}->"
                        f"{_decimal_to_canonical_str(curr.volume_lots)}"
                    )
                    pending_events.append(
                        ExecutionEvent(
                            event_id=event_id,
                            event_type=ExecutionEventType.PARTIAL_FILL,
                            broker_id=self._broker_id,
                            symbol=curr.symbol,
                            order_id=curr.order_id,
                            position_ticket=curr.ticket,
                            side=curr.side,
                            quantity_lots=delta_lots,
                            price=fill_price,
                            realized_pnl_usd=realized_pnl,
                            timestamp_utc=event_ts,
                            stop_loss=curr.stop_loss,
                            take_profit=curr.take_profit,
                            reason=action_note,
                        )
                    )

                if curr.stop_loss != prev.stop_loss or curr.take_profit != prev.take_profit:
                    prev_sl = _opt_decimal_key(prev.stop_loss)
                    curr_sl = _opt_decimal_key(curr.stop_loss)
                    prev_tp = _opt_decimal_key(prev.take_profit)
                    curr_tp = _opt_decimal_key(curr.take_profit)
                    amend_price = (
                        curr.stop_loss
                        if curr.stop_loss is not None
                        else (curr.take_profit if curr.take_profit is not None else curr.price_open)
                    )
                    event_id = (
                        f"mt5:{self._broker_id}:AMEND_STOP:{curr.ticket}:"
                        f"sl={prev_sl}->{curr_sl}:tp={prev_tp}->{curr_tp}"
                    )
                    pending_events.append(
                        ExecutionEvent(
                            event_id=event_id,
                            event_type=ExecutionEventType.AMEND_STOP,
                            broker_id=self._broker_id,
                            symbol=curr.symbol,
                            order_id=curr.order_id,
                            position_ticket=curr.ticket,
                            side=curr.side,
                            quantity_lots=curr.volume_lots,
                            price=amend_price,
                            realized_pnl_usd=Decimal("0"),
                            timestamp_utc=event_ts,
                            stop_loss=curr.stop_loss,
                            take_profit=curr.take_profit,
                            reason=f"sl:{prev_sl}->{curr_sl},tp:{prev_tp}->{curr_tp}",
                        )
                    )

            for ticket in sorted(prev_map):
                if ticket in current_map:
                    continue
                prev = prev_map[ticket]
                hint = close_hints.get(ticket, {}) if close_hints else {}
                event_type, close_price, realized_pnl, reason = self._classify_close(
                    prev=prev,
                    market_price=normalized_prices.get(prev.symbol),
                    hint=hint,
                )
                event_id = (
                    f"mt5:{self._broker_id}:{event_type.value}:{prev.ticket}:"
                    f"{_decimal_to_canonical_str(prev.volume_lots)}:"
                    f"{_decimal_to_canonical_str(close_price)}"
                )
                pending_events.append(
                    ExecutionEvent(
                        event_id=event_id,
                        event_type=event_type,
                        broker_id=self._broker_id,
                        symbol=prev.symbol,
                        order_id=prev.order_id,
                        position_ticket=prev.ticket,
                        side=prev.side,
                        quantity_lots=prev.volume_lots,
                        price=close_price,
                        realized_pnl_usd=realized_pnl,
                        timestamp_utc=event_ts,
                        stop_loss=prev.stop_loss,
                        take_profit=prev.take_profit,
                        reason=reason,
                    )
                )

            self._positions = current_map

        emitted: list[ExecutionEvent] = []
        for event in pending_events:
            stamped, is_new = self._bus.publish_idempotent(event)
            if is_new:
                emitted.append(stamped)
        return tuple(emitted)

    def _classify_close(
        self,
        *,
        prev: _NormalizedPosition,
        market_price: Decimal | None,
        hint: Mapping[str, Any],
    ) -> tuple[ExecutionEventType, Decimal, Decimal, str]:
        hint_reason = str(hint.get("reason", hint.get("close_reason", "")) or "").strip().upper()
        hint_price = _coerce_snapshot_decimal(
            hint.get("close_price", hint.get("price")),
            "close_price",
            allow_none=True,
        )
        hint_pnl = _coerce_snapshot_decimal(
            hint.get("realized_pnl_usd"),
            "realized_pnl_usd",
            allow_none=True,
        )
        realized_pnl = prev.profit if hint_pnl is None else hint_pnl
        close_price = hint_price if hint_price is not None else market_price

        if hint_reason in ("SL", "SL_HIT", "STOP_LOSS"):
            resolved_px = close_price if close_price is not None else (
                prev.stop_loss if prev.stop_loss is not None else prev.price_open
            )
            return ExecutionEventType.SL_HIT, resolved_px, realized_pnl, "stop_loss_hit"

        if hint_reason in ("TP", "TP_HIT", "TAKE_PROFIT"):
            resolved_px = close_price if close_price is not None else (
                prev.take_profit if prev.take_profit is not None else prev.price_open
            )
            return ExecutionEventType.TP_HIT, resolved_px, realized_pnl, "take_profit_hit"

        if hint_reason in ("MANUAL", "CLOSE_MANUAL", "USER"):
            resolved_px = close_price if close_price is not None else prev.price_open
            return ExecutionEventType.CLOSE_MANUAL, resolved_px, realized_pnl, "manual_close"

        if close_price is not None:
            if prev.side == Side.BUY.value:
                if prev.stop_loss is not None and close_price <= prev.stop_loss + self._price_tolerance:
                    return ExecutionEventType.SL_HIT, close_price, realized_pnl, "stop_loss_hit"
                if prev.take_profit is not None and close_price >= prev.take_profit - self._price_tolerance:
                    return ExecutionEventType.TP_HIT, close_price, realized_pnl, "take_profit_hit"
            elif prev.side == Side.SELL.value:
                if prev.stop_loss is not None and close_price >= prev.stop_loss - self._price_tolerance:
                    return ExecutionEventType.SL_HIT, close_price, realized_pnl, "stop_loss_hit"
                if prev.take_profit is not None and close_price <= prev.take_profit + self._price_tolerance:
                    return ExecutionEventType.TP_HIT, close_price, realized_pnl, "take_profit_hit"
            return ExecutionEventType.CLOSE_MANUAL, close_price, realized_pnl, "manual_close"

        return ExecutionEventType.CLOSE_MANUAL, prev.price_open, realized_pnl, "manual_close"
