"""Strictly read-only, opt-in Telegram alert notifier (zero trading/control authority)."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import http.client
import json
import logging
import os
import queue
import re
import ssl
import threading
import time
from typing import Any, Callable, Mapping

logger = logging.getLogger(__name__)

ENV_TELEGRAM_ALERTS_ENABLED = "CAS_FOREX_TELEGRAM_ALERTS_ENABLED"
ENV_TELEGRAM_BOT_TOKEN = "CAS_FOREX_TELEGRAM_BOT_TOKEN"  # nosec B105: environment variable name only
ENV_TELEGRAM_CHAT_ID = "CAS_FOREX_TELEGRAM_CHAT_ID"

TELEGRAM_API_HOST = "api.telegram.org"
TELEGRAM_ALERTS_SCHEMA = "cas-forex.telegram-alerts/1"

_SAFE_BOT_TOKEN_RE = re.compile(r"^[0-9A-Za-z:_-]{10,128}$")
_SAFE_CHAT_ID_RE = re.compile(r"^-?[0-9]{5,20}$")
_TRUTHY_VALUES = frozenset({"1", "true", "yes", "on"})
_MAX_QUEUE_SIZE = 64
_MAX_RECENT_ALERTS = 50
_MAX_MESSAGE_LEN = 3800


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_text(raw: object, *, max_len: int = 120, fallback: str = "") -> str:
    if raw is None:
        return fallback
    txt = "".join(ch for ch in str(raw) if ch == "\n" or ord(ch) >= 32).strip()
    return txt[:max_len] if txt else fallback


def _mode_prefix(execution_mode: object) -> str:
    mode = str(execution_mode or "").strip().upper()
    return "[LIVE]" if mode == "LIVE" else "[DEMO]"


def _valid_bot_token(token: object) -> str | None:
    if not isinstance(token, str):
        return None
    clean = token.strip()
    if not clean or not _SAFE_BOT_TOKEN_RE.match(clean):
        return None
    return clean


def _valid_chat_id(chat_id: object) -> str | None:
    if not isinstance(chat_id, str):
        return None
    clean = chat_id.strip()
    if not clean or not _SAFE_CHAT_ID_RE.match(clean):
        return None
    return clean


class TelegramAlertNotifier:
    """Bounded, non-blocking outbound-only Telegram notifier with zero trading authority."""

    read_only: bool = True
    trading_authority: str = "NONE"

    def __init__(
        self,
        *,
        enabled: bool = False,
        bot_token: str | None = None,
        chat_id: str | None = None,
        min_interval_seconds: float = 2.0,
        timeout_seconds: float = 4.0,
        transport: Callable[[str, str], tuple[int, bytes]] | None = None,
        clock: Callable[[], datetime] | None = None,
        mono_clock: Callable[[], float] | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._requested_enabled = bool(enabled)
        self._bot_token = _valid_bot_token(bot_token)
        self._chat_id = _valid_chat_id(chat_id)
        self._configured = bool(self._bot_token is not None and self._chat_id is not None)
        self._enabled = bool(self._requested_enabled and self._configured)
        self._min_interval_seconds = max(0.0, float(min_interval_seconds))
        self._timeout_seconds = max(0.5, min(15.0, float(timeout_seconds)))
        self._transport = transport
        self._clock = clock or _utc_now
        self._mono_clock = mono_clock or time.monotonic

        self._sent_count = 0
        self._dropped_count = 0
        self._error_count = 0
        self._last_sent_at: str | None = None
        self._last_event_kind: str | None = None
        self._recent_alerts: deque[dict[str, str]] = deque(maxlen=_MAX_RECENT_ALERTS)
        self._last_dispatch_mono: float | None = None

        self._queue: queue.Queue[dict[str, str] | None] = queue.Queue(maxsize=_MAX_QUEUE_SIZE)
        self._closed = False
        self._worker: threading.Thread | None = None
        if self._enabled:
            self._worker = threading.Thread(
                target=self._worker_loop,
                name="cas-forex-telegram-alerts",
                daemon=True,
            )
            self._worker.start()

    def __repr__(self) -> str:
        return (
            f"TelegramAlertNotifier(enabled={self._enabled}, configured={self._configured}, "
            f"read_only=True, trading_authority='NONE')"
        )

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        min_interval_seconds: float = 2.0,
        timeout_seconds: float = 4.0,
        transport: Callable[[str, str], tuple[int, bytes]] | None = None,
        clock: Callable[[], datetime] | None = None,
        mono_clock: Callable[[], float] | None = None,
    ) -> "TelegramAlertNotifier":
        src = os.environ if env is None else env
        raw_enabled = str(src.get(ENV_TELEGRAM_ALERTS_ENABLED, "false")).strip().lower()
        enabled = raw_enabled in _TRUTHY_VALUES
        return cls(
            enabled=enabled,
            bot_token=src.get(ENV_TELEGRAM_BOT_TOKEN),
            chat_id=src.get(ENV_TELEGRAM_CHAT_ID),
            min_interval_seconds=min_interval_seconds,
            timeout_seconds=timeout_seconds,
            transport=transport,
            clock=clock,
            mono_clock=mono_clock,
        )

    def close(self, *, timeout: float = 2.0) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            worker = self._worker
        if worker is not None:
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    pass
                try:
                    self._queue.put_nowait(None)
                except queue.Full:
                    pass
            worker.join(timeout=max(0.1, float(timeout)))

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "schema": TELEGRAM_ALERTS_SCHEMA,
                "read_only": True,
                "trading_authority": "NONE",
                "enabled": bool(self._enabled),
                "configured": bool(self._configured),
                "status": "ACTIVE" if self._enabled else "STANDBY",
                "sent_count": int(self._sent_count),
                "dropped_count": int(self._dropped_count),
                "error_count": int(self._error_count),
                "last_sent_at": self._last_sent_at,
                "last_event_kind": self._last_event_kind,
                "recent_alerts": [dict(item) for item in self._recent_alerts],
            }

    def enqueue_alert(self, *, event_kind: str, text: str) -> bool:
        """Queue an outbound-only alert without blocking trade or 50ms stop loops."""
        kind = _clean_text(event_kind, max_len=48, fallback="ALERT").upper().replace(" ", "_")
        body = _clean_text(text, max_len=_MAX_MESSAGE_LEN, fallback="")
        if not body:
            return False
        ts = _iso_utc(self._clock())
        with self._lock:
            self._recent_alerts.appendleft(
                {
                    "observed_at": ts,
                    "event_kind": kind,
                    "summary": body.replace("\n", " | ")[:240],
                }
            )
            self._last_event_kind = kind
            if not self._enabled or self._closed:
                return False
            try:
                self._queue.put_nowait({"event_kind": kind, "text": body, "observed_at": ts})
                return True
            except queue.Full:
                self._dropped_count += 1
                logger.warning("Telegram alert queue full; dropped %s alert", kind)
                return False

    def notify_trade_opened(
        self,
        *,
        execution_mode: str,
        broker_id: str,
        symbol: str,
        side: str,
        volume_lots: Any,
        entry_price: Any,
        stop_loss: Any = None,
        take_profit: Any = None,
    ) -> bool:
        pfx = _mode_prefix(execution_mode)
        sym = _clean_text(symbol, max_len=24, fallback="UNKNOWN")
        s_side = _clean_text(side, max_len=12, fallback="BUY").upper()
        brk = _clean_text(broker_id, max_len=32, fallback="BROKER")
        sl_txt = _clean_text(stop_loss, max_len=32, fallback="None")
        tp_txt = _clean_text(take_profit, max_len=32, fallback="None")
        msg = (
            f"{pfx} Trade Opened: {sym} {s_side} {volume_lots} lots on {brk} "
            f"@ {entry_price} | Stop {sl_txt} | Target {tp_txt}"
        )
        return self.enqueue_alert(event_kind="TRADE_OPENED", text=msg)

    def notify_breakeven_locked(
        self,
        *,
        execution_mode: str,
        broker_id: str,
        symbol: str,
        ticket: str,
        new_stop_loss: Any,
        stage: str = "BREAKEVEN_LOCKED",
    ) -> bool:
        pfx = _mode_prefix(execution_mode)
        sym = _clean_text(symbol, max_len=24, fallback="UNKNOWN")
        brk = _clean_text(broker_id, max_len=32, fallback="BROKER")
        tkt = _clean_text(ticket, max_len=48, fallback="UNKNOWN")
        stg = _clean_text(stage, max_len=32, fallback="BREAKEVEN_LOCKED")
        msg = (
            f"{pfx} Protection Updated ({stg}): {sym} #{tkt} on {brk} "
            f"moved Stop to {new_stop_loss}"
        )
        return self.enqueue_alert(event_kind="BREAKEVEN_LOCKED", text=msg)

    def notify_trade_closed(
        self,
        *,
        execution_mode: str,
        broker_id: str,
        symbol: str,
        ticket: str,
        realized_pnl_usd: Any,
        reason: str = "CLOSED",
    ) -> bool:
        pfx = _mode_prefix(execution_mode)
        sym = _clean_text(symbol, max_len=24, fallback="UNKNOWN")
        brk = _clean_text(broker_id, max_len=32, fallback="BROKER")
        tkt = _clean_text(ticket, max_len=48, fallback="UNKNOWN")
        rsn = _clean_text(reason, max_len=80, fallback="CLOSED")
        msg = (
            f"{pfx} Trade Closed: {sym} #{tkt} on {brk} | "
            f"Realized P/L: ${realized_pnl_usd} USD ({rsn})"
        )
        return self.enqueue_alert(event_kind="TRADE_CLOSED", text=msg)

    def notify_demo_replenished(
        self,
        *,
        lane: str,
        previous_balance_usd: Any,
        added_usd: Any,
        new_balance_usd: Any,
        trigger: str = "AUTO_FLOOR",
    ) -> bool:
        ln = _clean_text(lane, max_len=48, fallback="DEMO")
        trg = _clean_text(trigger, max_len=48, fallback="AUTO_FLOOR")
        msg = (
            f"[DEMO] Practice Capital Replenished ({ln} / {trg}): "
            f"${previous_balance_usd} + ${added_usd} -> ${new_balance_usd} USD"
        )
        return self.enqueue_alert(event_kind="DEMO_REPLENISHED", text=msg)

    def notify_profit_floor_locked(
        self,
        *,
        execution_mode: str,
        realized_net_pnl_usd: Any,
        protected_floor_usd: Any,
        session_date: str = "",
    ) -> bool:
        pfx = _mode_prefix(execution_mode)
        sdate = _clean_text(session_date, max_len=32, fallback="")
        sess_note = f" ({sdate})" if sdate else ""
        msg = (
            f"{pfx} Profit Floor Locked{sess_note}: Session Net ${realized_net_pnl_usd} USD | "
            f"Protected Floor ${protected_floor_usd} USD (AI entered Research Respite)"
        )
        return self.enqueue_alert(event_kind="PROFIT_FLOOR_LOCKED", text=msg)

    def _send_via_pinned_https(self, path: str, body_json: str) -> tuple[int, bytes]:
        if self._transport is not None:
            return self._transport(path, body_json)
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(
            TELEGRAM_API_HOST,
            443,
            timeout=self._timeout_seconds,
            context=ctx,
        )
        try:
            conn.request(
                "POST",
                path,
                body=body_json.encode("utf-8"),
                headers={
                    "Host": TELEGRAM_API_HOST,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            resp = conn.getresponse()
            raw = resp.read(4096)
            return int(resp.status), raw
        finally:
            conn.close()

    def _dispatch_item(self, item: dict[str, str]) -> bool:
        token = self._bot_token
        chat_id = self._chat_id
        if not token or not chat_id:
            return False
        if self._min_interval_seconds > 0.0:
            with self._lock:
                last_m = self._last_dispatch_mono
            now_m = self._mono_clock()
            if last_m is not None:
                wait_s = self._min_interval_seconds - (now_m - last_m)
                if wait_s > 0.0:
                    time.sleep(min(wait_s, self._min_interval_seconds))
        path = f"/bot{token}/sendMessage"
        payload = json.dumps(
            {
                "chat_id": chat_id,
                "text": item["text"],
                "disable_web_page_preview": True,
            }
        )
        try:
            status_code, _ = self._send_via_pinned_https(path, payload)
            with self._lock:
                self._last_dispatch_mono = self._mono_clock()
                if 200 <= status_code < 300:
                    self._sent_count += 1
                    self._last_sent_at = _iso_utc(self._clock())
                    return True
                self._error_count += 1
            logger.warning("Telegram alert HTTP error status=%s for %s", status_code, item["event_kind"])
            return False
        except Exception as exc:
            with self._lock:
                self._last_dispatch_mono = self._mono_clock()
                self._error_count += 1
            # Never log request path or exc details that could echo credentials
            logger.warning("Telegram alert delivery failed (%s) for %s", type(exc).__name__, item["event_kind"])
            return False

    def _worker_loop(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                self._dispatch_item(item)
            finally:
                self._queue.task_done()


__all__ = [
    "ENV_TELEGRAM_ALERTS_ENABLED",
    "ENV_TELEGRAM_BOT_TOKEN",
    "ENV_TELEGRAM_CHAT_ID",
    "TELEGRAM_ALERTS_SCHEMA",
    "TELEGRAM_API_HOST",
    "TelegramAlertNotifier",
]
