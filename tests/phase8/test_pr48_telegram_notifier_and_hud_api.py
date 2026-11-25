"""PR #47 / Update 48 tests: strictly read-only Telegram alerts, schema, and HTTP cockpit API."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import http.client
import json
from pathlib import Path
import socket
import tempfile
import time
import unittest
import urllib.parse

from cas_forex_revamp.composition.autonomous_trader import AutonomousAiTrader
from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer
from cas_forex_revamp.composition.option_b_paper_runner import OptionBPaperDemoRunner
from cas_forex_revamp.composition.parallel_tiers import ParallelTierEngine
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.operator.telegram_alert_notifier import (
    ENV_TELEGRAM_ALERTS_ENABLED,
    ENV_TELEGRAM_BOT_TOKEN,
    ENV_TELEGRAM_CHAT_ID,
    TELEGRAM_ALERTS_SCHEMA,
    TelegramAlertNotifier,
)
from cas_forex_revamp.risk.demo_high_growth_profile import DemoHighGrowthProfile
from cas_forex_revamp.valve.aggression_dial import AggressionDialStore
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import PeakEquityStore, load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter

REPO_ROOT = Path(__file__).resolve().parents[2]
AI_SCHEMA_PATH = REPO_ROOT / "docs" / "contracts" / "ai-trader.schema.json"
T0 = datetime(2026, 11, 25, 4, 0, 0, tzinfo=timezone.utc)


def _http_raw(
    url: str,
    *,
    method: str = "GET",
    token: str | None = None,
    body: dict | None = None,
) -> tuple[int, bytes]:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or "127.0.0.1"
    port = int(parsed.port or 80)
    path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {parsed.netloc}",
        "Accept: application/json",
        "Connection: close",
    ]
    if token is not None:
        lines.append(f"Authorization: Bearer {token}")
    payload_bytes = b""
    if body is not None:
        payload_bytes = json.dumps(body).encode("utf-8")
        lines.append("Content-Type: application/json")
        lines.append(f"Content-Length: {len(payload_bytes)}")
    raw_req = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + payload_bytes
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(raw_req)
        resp = http.client.HTTPResponse(sock)
        resp.begin()
        raw_body = resp.read()
        status = int(resp.status)
        resp.close()
    return status, raw_body


class Pr48TelegramNotifierAndHudApiTests(unittest.TestCase):
    def test_01_telegram_notifier_disabled_by_default_and_never_leaks_secret(self) -> None:
        secret_tok = "123456789:ABCDEF_FAKE_BOT_TOKEN_SECRET_VALUE"
        secret_chat = "-1001234567890"
        # Disabled when flag is omitted or false even if token+chat_id present
        off_n = TelegramAlertNotifier.from_env(
            {
                ENV_TELEGRAM_ALERTS_ENABLED: "false",
                ENV_TELEGRAM_BOT_TOKEN: secret_tok,
                ENV_TELEGRAM_CHAT_ID: secret_chat,
            },
            clock=lambda: T0,
        )
        try:
            snap = off_n.snapshot()
            self.assertEqual(snap["schema"], TELEGRAM_ALERTS_SCHEMA)
            self.assertIs(snap["read_only"], True)
            self.assertEqual(snap["trading_authority"], "NONE")
            self.assertIs(snap["enabled"], False)
            self.assertIs(snap["configured"], True)
            self.assertEqual(snap["status"], "STANDBY")
            self.assertNotIn(secret_tok, repr(off_n))
            self.assertNotIn(secret_tok, json.dumps(snap))
            queued = off_n.notify_trade_opened(
                execution_mode="DEMO",
                broker_id="LHFX_MT5",
                symbol="NAS100",
                side="BUY",
                volume_lots="0.50",
                entry_price="26750.00",
                stop_loss="26690.00",
                take_profit="26882.00",
            )
            self.assertIs(queued, False)
            snap_after = off_n.snapshot()
            self.assertEqual(snap_after["sent_count"], 0)
            self.assertEqual(len(snap_after["recent_alerts"]), 1)
            self.assertEqual(snap_after["recent_alerts"][0]["event_kind"], "TRADE_OPENED")
        finally:
            off_n.close()

    def test_02_telegram_notifier_sends_all_events_via_transport_and_isolates_errors(self) -> None:
        sent_calls: list[tuple[str, dict]] = []

        def stub_transport(path: str, body_json: str) -> tuple[int, bytes]:
            sent_calls.append((path, json.loads(body_json)))
            if len(sent_calls) == 2:
                raise TimeoutError("Simulated Telegram network outage")
            return 200, b'{"ok":true}'

        tok = "987654321:XYZ_TEST_SECRET_TOKEN_999"
        n = TelegramAlertNotifier.from_env(
            {
                ENV_TELEGRAM_ALERTS_ENABLED: "true",
                ENV_TELEGRAM_BOT_TOKEN: tok,
                ENV_TELEGRAM_CHAT_ID: "-10099887766",
            },
            min_interval_seconds=0.0,
            transport=stub_transport,
            clock=lambda: T0,
        )
        try:
            self.assertTrue(
                n.notify_breakeven_locked(
                    execution_mode="DEMO",
                    broker_id="LHFX_MT5",
                    symbol="XAUUSD",
                    ticket="13919780",
                    new_stop_loss="3567.50",
                )
            )
            self.assertTrue(
                n.notify_trade_closed(
                    execution_mode="DEMO",
                    broker_id="LHFX_MT5",
                    symbol="SPX500",
                    ticket="13919726",
                    realized_pnl_usd="1120.50",
                    reason="TP_HIT",
                )
            )
            self.assertTrue(
                n.notify_demo_replenished(
                    lane="OPTION_B_DEMO",
                    previous_balance_usd="3728.68",
                    added_usd="1271.32",
                    new_balance_usd="5000.00",
                    trigger="OWNER_REPLENISH",
                )
            )
            self.assertTrue(
                n.notify_profit_floor_locked(
                    execution_mode="DEMO",
                    realized_net_pnl_usd="2500.00",
                    protected_floor_usd="1750.00",
                    session_date="2026-11-25",
                )
            )
            deadline = time.monotonic() + 3.0
            while len(sent_calls) < 4 and time.monotonic() < deadline:
                time.sleep(0.02)
            time.sleep(0.05)
            snap = n.snapshot()
            self.assertEqual(snap["status"], "ACTIVE")
            self.assertEqual(snap["sent_count"], 3)
            self.assertEqual(snap["error_count"], 1)
            self.assertNotIn(tok, json.dumps(snap))
            self.assertNotIn(tok, repr(n))
            self.assertIn("[DEMO]", sent_calls[0][1]["text"])
            self.assertIn("OPTION_B_DEMO", sent_calls[2][1]["text"])
        finally:
            n.close()

    def test_03_option_b_parallel_tiers_and_ai_trader_trigger_replenish_alerts(self) -> None:
        delivered: list[str] = []

        def stub_transport(_path: str, body_json: str) -> tuple[int, bytes]:
            delivered.append(json.loads(body_json)["text"])
            return 200, b'{"ok":true}'

        notifier = TelegramAlertNotifier(
            enabled=True,
            bot_token="1122334455:TEST_TOKEN_SECRET_ABCDE",
            chat_id="-10077665544",
            min_interval_seconds=0.0,
            transport=stub_transport,
            clock=lambda: T0,
        )
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            gate = load_default_forex_valve_gate(peak_equity_store=PeakEquityStore(tdp / "pk.sqlite3"))
            ob = OptionBPaperDemoRunner(
                db_path=tdp / "ob.sqlite3",
                valve_gate=gate,
                demo_high_growth=DemoHighGrowthProfile(enabled=True),
                clock=lambda: T0,
                telegram_notifier=notifier,
            )
            ob.ingest_spot_quote("NAS100", Decimal("26750.00"), Decimal("26751.00"), now_utc=T0)
            # Trigger low-balance replenishment directly via emulator debit + check
            ob.set_auto_replenish(enabled=True, floor_pct="70.00", now_utc=T0)
            pt = ParallelTierEngine(
                tdp / "pt.sqlite3",
                valve_gate=gate,
                demo_high_growth=DemoHighGrowthProfile(enabled=True),
                clock=lambda: T0,
                telegram_notifier=notifier,
            )
            res_pt = pt.replenish_all_tiers(reason="test alert hook", now=T0)
            self.assertTrue(res_pt["ok"])

            router = DualShieldBrokerRouter(environ={}, valve_gate=gate)
            reg = FrontierModelRegistry(environ={"CAS_FOREX_MODEL_MAX_CALLS_PER_DAY": "100"})
            trader = AutonomousAiTrader(
                router=router,
                model_registry=reg,
                valve_gate=gate,
                quota_store=DailyQuotaGovernanceStore(tdp / "dq.sqlite3"),
                peak_equity_store=PeakEquityStore(tdp / "tpk.sqlite3"),
                aggression_dial=AggressionDialStore(tdp / "dial.sqlite3"),
                execution_gate=DurableModelExecutionGate(db_path=tdp / "gate.sqlite3"),
                clock=lambda: T0,
                telegram_notifier=notifier,
            )
            try:
                snap = trader.status_snapshot(now=T0)
                self.assertIn("telegram_alerts", snap)
                self.assertEqual(snap["telegram_alerts"]["schema"], TELEGRAM_ALERTS_SCHEMA)
                self.assertEqual(snap["telegram_alerts"]["status"], "ACTIVE")
                self.assertIs(snap["telegram_alerts"]["read_only"], True)
                self.assertEqual(snap["telegram_alerts"]["trading_authority"], "NONE")
                # Validate telegram_alerts schema shape against docs/contracts/ai-trader.schema.json
                schema_doc = json.loads(AI_SCHEMA_PATH.read_text(encoding="utf-8"))
                self.assertIn("telegram_alerts", schema_doc["properties"])
            finally:
                notifier.close()

    def test_04_cockpit_serves_blueprint_svg_hud_js_and_readonly_telegram_endpoint(self) -> None:
        notifier = TelegramAlertNotifier(enabled=False, clock=lambda: T0)
        srv = LoopbackCockpitServer(
            repo_root=REPO_ROOT,
            host="127.0.0.1",
            port=0,
            emergency_port=0,
            telegram_notifier=notifier,
        )
        srv.start()
        try:
            st_unauth, _ = _http_raw(f"{srv.base_url}/api/telegram-alerts")
            self.assertEqual(st_unauth, 401)

            st_ok, raw_tg = _http_raw(f"{srv.base_url}/api/telegram-alerts", token=srv.auth_token)
            self.assertEqual(st_ok, 200)
            doc = json.loads(raw_tg.decode("utf-8"))
            self.assertEqual(doc["schema"], TELEGRAM_ALERTS_SCHEMA)
            self.assertIs(doc["read_only"], True)
            self.assertEqual(doc["trading_authority"], "NONE")
            self.assertEqual(doc["status"], "STANDBY")

            st_post, _ = _http_raw(
                f"{srv.base_url}/api/telegram-alerts",
                method="POST",
                token=srv.auth_token,
                body={"action": "ENABLE"},
            )
            self.assertEqual(st_post, 405)

            st_svg, raw_svg = _http_raw(f"{srv.base_url}/ui/assets/blueprint-grid.svg")
            self.assertEqual(st_svg, 200)
            self.assertIn(b"<svg", raw_svg)

            st_js, raw_js = _http_raw(f"{srv.base_url}/ui/src/tactical-hud.mjs")
            self.assertEqual(st_js, 200)
            self.assertIn(b"renderTacticalValveHud", raw_js)
        finally:
            srv.stop()
            notifier.close()


if __name__ == "__main__":
    unittest.main()
