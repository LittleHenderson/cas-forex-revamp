"""PR #46 / Update 47 tests: DEMO-only 70% auto-replenish, replenish actions, & Hugo's Way exclusion."""

from __future__ import annotations

import contextlib
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import http.client
import json
from pathlib import Path
import re
import socket
import sqlite3
import tempfile
import unittest
import urllib.parse

from cas_forex_revamp.composition.autonomous_trader import (
    AutonomousAiTrader,
    DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE,
    DEMO_REPLENISH_REQUIRES_FLAT_POSITIONS,
)
from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer
from cas_forex_revamp.composition.option_b_paper_runner import OptionBPaperDemoRunner
from cas_forex_revamp.composition.parallel_tiers import ParallelTierEngine
from cas_forex_revamp.contracts import ContractError, canonical_bytes
from cas_forex_revamp.futures.tradovate_venue import (
    TRADOVATE_MODE_DEMO,
    TRADOVATE_MODE_LIVE,
    TradovateLiveLockError,
    TradovateMicroFuturesPaperEmulator,
    TradovateMicroFuturesVenue,
)
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.risk.demo_high_growth_profile import DemoHighGrowthProfile
from cas_forex_revamp.valve.aggression_dial import AggressionDialStore
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    PeakEquityStore,
    ValveDecision,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.external_paper_broker import (
    ENV_OANDA_PRACTICE_ACCOUNT_ID,
    ENV_OANDA_PRACTICE_TOKEN,
    OandaPracticePaperClient,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    ENV_EXECUTION_MODE,
    ENV_HUGOSWAY_MT5_LOGIN,
    ENV_HUGOSWAY_MT5_PASSWORD,
    ENV_HUGOSWAY_MT5_SERVER,
    ENV_LHFX_MT5_LOGIN,
    ENV_LHFX_MT5_SERVER,
    ENV_MT5_SPOOL_DIR,
    ENV_MT5_TRANSPORT_MODE,
    EXECUTION_MODE_DEMO,
    EXECUTION_MODE_LIVE,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    TRANSPORT_SPOOL_BRIDGE,
)

D = Decimal
T0 = datetime(2026, 11, 24, 15, 0, 0, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[2]
OB_SCHEMA_PATH = REPO_ROOT / "docs" / "contracts" / "option-b-demo.schema.json"
PT_SCHEMA_PATH = REPO_ROOT / "docs" / "contracts" / "parallel-tiers.schema.json"
AI_SCHEMA_PATH = REPO_ROOT / "docs" / "contracts" / "ai-trader.schema.json"


def _fixture_str(slot: str) -> str:
    return f"pr47-fixture-{slot}"


class _MutableClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int | float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


class _StubValveGate:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed

    def evaluate(self, proposal, *, current_view=None, policy=None, now=None) -> ValveDecision:
        return ValveDecision(
            admitted=self.allowed,
            valve_mode="ADMITTED" if self.allowed else "MLP_SCORE_VETO",
            mlp_score=0.91 if self.allowed else 0.12,
            threshold=0.55,
            mlp_admitted=self.allowed,
            hard_veto=not self.allowed,
            hard_veto_reasons=() if self.allowed else ("TEST_VETO",),
            features={},
            weights_sha256="a" * 64,
            request_id=proposal.request.request_id,
            selected_action_ref=proposal.result.selection.selected_action_ref,
        )


class _StubOandaTransport:
    def __init__(self, *, account_id: str = "101-001-4700001-001", equity: str = "100000.00") -> None:
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


def _open_first_choice_http():
    def _post(_url: str, _hdrs: object, body: bytes, *_args: object) -> tuple[int, bytes]:
        body_doc = json.loads(body.decode("utf-8"))
        user_doc = json.loads(body_doc["messages"][0]["content"])
        ref = user_doc["options"][0]["action_ref"]
        sel = {
            "request_id": user_doc["request_id"],
            "opportunity_set_id": user_doc["opportunity_set_id"],
            "source_state_id": user_doc["state"]["state_id"],
            "selected_action_ref": ref,
            "reason": f"ID=0{ref} approved pr47",
            "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]],
        }
        return 200, json.dumps({
            "content": [{"type": "text", "text": json.dumps(sel)}],
            "usage": {"output_tokens": 32},
        }).encode("utf-8")

    return _post


def _http_json(
    url: str,
    *,
    method: str = "GET",
    token: str | None = None,
    body: dict | None = None,
) -> tuple[int, dict]:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or "127.0.0.1"
    port = int(parsed.port or 80)
    path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    req_lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {parsed.netloc}",
        "Accept: application/json",
        "Connection: close",
    ]
    if token is not None:
        req_lines.append(f"Authorization: Bearer {token}")
    data: bytes | None = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        req_lines.append("Content-Type: application/json")
        req_lines.append(f"Content-Length: {len(data)}")
    raw_req = ("\r\n".join(req_lines) + "\r\n\r\n").encode("ascii") + (data or b"")
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(raw_req)
        resp = http.client.HTTPResponse(sock)
        resp.begin()
        raw = resp.read().decode("utf-8", errors="replace")
        status = int(resp.status)
        resp.close()
    try:
        payload = json.loads(raw)
    except Exception:
        payload = {"raw": raw}
    return status, payload


_SCHEMA_TYPE_CHECKS = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def _resolve_ref(ref: str, root_schema: dict) -> dict:
    if not ref.startswith("#/$defs/"):
        raise ValueError(f"Unsupported schema ref: {ref}")
    key = ref.split("/", 2)[2]
    return root_schema["$defs"][key]


def _validate_node(value: object, subschema: dict, root_schema: dict, path: str) -> list[str]:
    if "$ref" in subschema:
        subschema = _resolve_ref(subschema["$ref"], root_schema)
    if "anyOf" in subschema:
        for opt in subschema["anyOf"]:
            if not _validate_node(value, opt, root_schema, path):
                return []
        return [f"{path}: value {value!r} matched none of anyOf"]
    errors: list[str] = []
    if "const" in subschema:
        expected = subschema["const"]
        if value != expected or type(value) is not type(expected):
            errors.append(f"{path}: expected const {expected!r}, got {value!r}")
    if "enum" in subschema:
        if not any(value == opt and type(value) is type(opt) for opt in subschema["enum"]):
            errors.append(f"{path}: {value!r} not in enum")
    if "type" in subschema:
        raw_types = subschema["type"]
        expected_types = [raw_types] if isinstance(raw_types, str) else list(raw_types)
        if not any(_SCHEMA_TYPE_CHECKS[t](value) for t in expected_types):
            errors.append(f"{path}: bad type {type(value).__name__}")
            return errors
    if isinstance(value, str):
        if "minLength" in subschema and len(value) < int(subschema["minLength"]):
            errors.append(f"{path}: len < minLength")
        if "maxLength" in subschema and len(value) > int(subschema["maxLength"]):
            errors.append(f"{path}: len > maxLength")
        if "pattern" in subschema and re.search(str(subschema["pattern"]), value) is None:
            errors.append(f"{path}: {value!r} failed pattern {subschema['pattern']!r}")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in subschema and value < subschema["minimum"]:
            errors.append(f"{path}: < minimum")
    if isinstance(value, list):
        item_schema = subschema.get("items")
        if isinstance(item_schema, dict):
            for idx, item in enumerate(value):
                errors.extend(_validate_node(item, item_schema, root_schema, f"{path}[{idx}]"))
    if isinstance(value, dict):
        props = subschema.get("properties", {})
        for req_key in subschema.get("required", []):
            if req_key not in value:
                errors.append(f"{path}.{req_key}: missing required key")
        if subschema.get("additionalProperties") is False:
            extra = sorted(set(value.keys()) - set(props.keys()))
            if extra:
                errors.append(f"{path}: extra keys {extra}")
        for k, v in value.items():
            if k in props:
                errors.extend(_validate_node(v, props[k], root_schema, f"{path}.{k}"))
    return errors


def _validate_doc(doc: dict, schema_path: Path) -> list[str]:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    return _validate_node(doc, schema, schema, "$")


def _seed_pre_u47_option_b_db(db_path: Path) -> None:
    ts = T0.strftime("%Y-%m-%dT%H:%M:%SZ")
    with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE option_b_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                account_id TEXT NOT NULL,
                starting_equity_usd TEXT NOT NULL,
                last_balance_usd TEXT NOT NULL,
                peak_equity_usd TEXT NOT NULL,
                total_realized_pnl_usd TEXT NOT NULL,
                total_commissions_usd TEXT NOT NULL,
                vault_50pct_reserved_usd TEXT NOT NULL,
                retained_compounding_usd TEXT NOT NULL,
                win_count INTEGER NOT NULL,
                loss_count INTEGER NOT NULL,
                house_money_target_usd TEXT NOT NULL,
                house_money_reached_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE option_b_closed_trades (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                trade_id TEXT NOT NULL UNIQUE,
                cas_symbol TEXT NOT NULL,
                root_symbol TEXT NOT NULL,
                contract_code TEXT NOT NULL,
                side TEXT NOT NULL,
                contracts INTEGER NOT NULL,
                exit_price TEXT NOT NULL,
                realized_pnl_usd TEXT NOT NULL,
                commission_usd TEXT NOT NULL,
                net_pnl_usd TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL,
                closed_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE option_b_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                cas_symbol TEXT NOT NULL,
                root_symbol TEXT NOT NULL,
                detail TEXT NOT NULL,
                occurred_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO option_b_meta VALUES (
                1, 'OPTION-B-PAPER-5K', '5000.00', '3728.68', '5080.00',
                '-1271.32', '12.40', '0.00', '0.00', 2, 4, '10000.00', NULL, ?, ?
            )
            """,
            (ts, ts),
        )
        for idx in range(6):
            net = "131.38" if idx < 2 else "-383.52"
            st = "TAKE_PROFIT_FILLED" if idx < 2 else "STOP_LOSS_FILLED"
            conn.execute(
                """
                INSERT INTO option_b_closed_trades VALUES (
                    NULL, ?, 'NAS100', 'MNQ', 'MNQZ6', 'BUY', 2, '26700.00', ?, '2.48', ?, ?, 'HIST_TRADE', ?
                )
                """,
                (f"hist-{idx}", net, net, st, ts),
            )
        conn.commit()


def _seed_pre_u47_parallel_tiers_db(db_path: Path) -> None:
    ts = T0.isoformat().replace("+00:00", "Z")
    with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE tier_accounts (
                tier_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                color_class TEXT NOT NULL,
                starting_capital_usd TEXT NOT NULL,
                balance_usd TEXT NOT NULL,
                equity_usd TEXT NOT NULL,
                peak_equity_usd TEXT NOT NULL,
                realized_net_usd TEXT NOT NULL,
                win_count INTEGER NOT NULL,
                loss_count INTEGER NOT NULL,
                gross_profit_usd TEXT NOT NULL,
                gross_loss_usd TEXT NOT NULL,
                last_skip_reason TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE tier_positions (
                ticket TEXT PRIMARY KEY,
                tier_id TEXT NOT NULL,
                symbol TEXT NOT NULL,
                side TEXT NOT NULL,
                units TEXT NOT NULL,
                entry_price TEXT NOT NULL,
                stop_loss TEXT NOT NULL,
                take_profit TEXT NOT NULL,
                initial_stop_loss TEXT,
                peak_favorable TEXT NOT NULL,
                protection_stage TEXT NOT NULL,
                entry_commission_usd TEXT NOT NULL,
                leg_index INTEGER NOT NULL DEFAULT 1,
                opened_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE tier_closed_trades (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                tier_id TEXT NOT NULL,
                ticket TEXT NOT NULL,
                symbol TEXT NOT NULL,
                side TEXT NOT NULL,
                units TEXT NOT NULL,
                entry_price TEXT NOT NULL,
                exit_price TEXT NOT NULL,
                realized_net_usd TEXT NOT NULL,
                close_reason TEXT NOT NULL,
                closed_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE tier_equity_history (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                tier_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                equity_usd TEXT NOT NULL,
                growth_pct TEXT NOT NULL
            )
            """
        )
        live_rows = [
            ("TIER_1_CURRENT", "Current Barbell ($300,000)", "tier-300k", "300000", "232284.71", "305000", "-67715.29", 3, 5, "12000", "79715.29", "VALVE_REFUSED (MAX_DRAWDOWN_EXCEEDED)"),
            ("TIER_2_1000", "Tier $1,000 Starter", "tier-1000", "1000", "794.15", "1000", "-205.85", 2, 4, "80", "285.85", "VALVE_REFUSED (MAX_DRAWDOWN_EXCEEDED)"),
            ("TIER_3_3000", "Tier $3,000 Growth", "tier-3000", "3000", "2407.51", "3000", "-592.49", 2, 4, "200", "792.49", None),
            ("TIER_4_6000", "Tier $6,000 Accelerator", "tier-6000", "6000", "4772.54", "6000", "-1227.46", 2, 4, "400", "1627.46", "VALVE_REFUSED (MAX_DRAWDOWN_EXCEEDED)"),
            ("TIER_5_300", "Tier $300 Micro Challenge", "tier-300", "300", "238.36", "300", "-61.64", 1, 3, "20", "81.64", None),
        ]
        for tid, lbl, ccls, st, bal, pk, net, w, l, gp, gl, skip in live_rows:
            conn.execute(
                "INSERT INTO tier_accounts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (tid, lbl, ccls, st, bal, bal, pk, net, w, l, gp, gl, skip, ts),
            )
            conn.execute(
                "INSERT INTO tier_equity_history VALUES (NULL, ?, ?, ?, '0')",
                (tid, ts, bal),
            )
            conn.execute(
                "INSERT INTO tier_closed_trades VALUES (NULL, ?, ?, 'NAS100', 'BUY', '0.01', '26800', '26750', ?, 'SL_HIT', ?)",
                (tid, f"closed-{tid}", net, ts),
            )
        conn.commit()


class Pr47DemoAutoReplenishTests(unittest.TestCase):
    def test_01_live_mode_hard_refused_everywhere(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            emu_live = TradovateMicroFuturesPaperEmulator(mode=TRADOVATE_MODE_LIVE, clock=lambda: T0)
            with self.assertRaises(ContractError) as ctx1:
                emu_live.replenish_demo_capital(D("5000.00"))
            self.assertEqual(str(ctx1.exception), DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)

            emu_demo = TradovateMicroFuturesPaperEmulator(mode=TRADOVATE_MODE_DEMO, clock=lambda: T0)
            venue = TradovateMicroFuturesVenue(
                db_path=root / "v.sqlite3",
                transport=emu_demo,
                valve_gate=_StubValveGate(allowed=True),
                mode=TRADOVATE_MODE_DEMO,
                clock=lambda: T0,
            )
            venue.activate(mode=TRADOVATE_MODE_DEMO, now_utc=T0)
            with self.assertRaises(ContractError) as ctx2:
                venue.replenish_demo_capital(D("5000.00"), execution_mode=EXECUTION_MODE_LIVE)
            self.assertEqual(str(ctx2.exception), DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)

            with self.assertRaises(TradovateLiveLockError):
                OptionBPaperDemoRunner(
                    db_path=root / "ob_live.sqlite3",
                    valve_gate=_StubValveGate(allowed=True),
                    mode=TRADOVATE_MODE_LIVE,
                )
            with self.assertRaises(ContractError) as ctx3:
                OptionBPaperDemoRunner(
                    db_path=root / "ob_armed.sqlite3",
                    valve_gate=_StubValveGate(allowed=True),
                    execution_mode=EXECUTION_MODE_LIVE,
                )
            self.assertEqual(str(ctx3.exception), DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)

            ob = OptionBPaperDemoRunner(
                db_path=root / "ob_demo.sqlite3",
                valve_gate=_StubValveGate(allowed=True),
                clock=lambda: T0,
            )
            with self.assertRaises(ContractError) as ctx4:
                ob.replenish_demo_capital(execution_mode=EXECUTION_MODE_LIVE)
            self.assertEqual(str(ctx4.exception), DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)
            with self.assertRaises(ContractError) as ctx5:
                ob.set_auto_replenish(enabled=True, live_trading_armed=True)
            self.assertEqual(str(ctx5.exception), DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)

            real_gate = load_default_forex_valve_gate()
            with self.assertRaises(ContractError) as ctx6:
                ParallelTierEngine(root / "pt_live.sqlite3", valve_gate=real_gate, execution_mode="LIVE")
            self.assertEqual(str(ctx6.exception), DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)

            pt = ParallelTierEngine(root / "pt_demo.sqlite3", valve_gate=real_gate, clock=lambda: T0)
            with self.assertRaises(ContractError) as ctx7:
                pt.replenish_all_tiers(execution_mode="LIVE")
            self.assertEqual(str(ctx7.exception), DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)
            with self.assertRaises(ContractError) as ctx8:
                pt.set_auto_replenish(enabled=True, live_trading_armed=True)
            self.assertEqual(str(ctx8.exception), DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)

            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                host="127.0.0.1",
                port=0,
                emergency_port=0,
                option_b_demo=ob,
                parallel_tiers=pt,
                broker_router_reader=lambda: {"execution_mode": "LIVE", "live_trading_armed": True},
            )
            srv.start()
            try:
                st_ob, doc_ob = _http_json(
                    f"{srv.base_url}/api/option-b-demo",
                    method="POST",
                    token=srv.auth_token,
                    body={"action": "REPLENISH_DEMO_CAPITAL"},
                )
                self.assertEqual(st_ob, 403)
                self.assertIn(DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE, str(doc_ob))

                st_pt, doc_pt = _http_json(
                    f"{srv.base_url}/api/parallel-tiers",
                    method="POST",
                    token=srv.auth_token,
                    body={"action": "REPLENISH_ALL_TIERS"},
                )
                self.assertEqual(st_pt, 403)
                self.assertIn(DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE, str(doc_pt))
            finally:
                srv.stop()

    def test_02_option_b_70pct_auto_replenish_prevents_deadlock_and_preserves_trades(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "option_b_paper_demo.sqlite3"
            _seed_pre_u47_option_b_db(db_path)

            runner = OptionBPaperDemoRunner(
                db_path=db_path,
                valve_gate=_StubValveGate(allowed=True),
                clock=clock,
            )
            snap_init = runner.snapshot()
            # $3,728.68 is above 70.00% ($3,500.00), so startup preserves $3,728.68 until owner/70% trigger
            self.assertEqual(snap_init["balance_usd"], "3728.68")
            self.assertEqual(snap_init["auto_replenish_floor_pct"], "70.00")
            self.assertEqual(snap_init["auto_replenish_floor_usd"], "3500.00")
            self.assertEqual(snap_init["closed_trades"], 6)
            self.assertEqual(_validate_doc(snap_init, OB_SCHEMA_PATH), [])

            # One-time owner replenish restores $3,728.68 -> $5,000.00 (+1271.32) with all 6 closed trades kept
            rep_manual = runner.replenish_demo_capital(reason="Deploy top-up")
            self.assertTrue(rep_manual["replenished"])
            self.assertEqual(rep_manual["added_usd"], "1271.32")
            snap_top = runner.snapshot()
            self.assertEqual(snap_top["balance_usd"], "5000.00")
            self.assertEqual(snap_top["peak_equity_usd"], "5000.00")
            self.assertEqual(snap_top["drawdown_pct"], "0.00")
            self.assertFalse(snap_top["drawdown_locked"])
            self.assertEqual(snap_top["replenishment_count"], 1)
            self.assertEqual(snap_top["cumulative_replenished_usd"], "1271.32")
            self.assertEqual(snap_top["closed_trades"], 6)
            self.assertTrue(snap_top["audit_chain_valid"])
            self.assertEqual(_validate_doc(snap_top, OB_SCHEMA_PATH), [])

            # Turn on High-Growth (10% risk, 30% DD brake = $3,500.00) and take losses to dip <= 70.00%
            runner.set_demo_high_growth_profile(DemoHighGrowthProfile(enabled=True))
            runner.ingest_spot_quote("NAS100", D("26800.00"), D("26801.00"), now_utc=clock())
            # Open 1 position and confirm flat-position guard refuses manual replenish while open
            clock.advance(2)
            r_open = runner.mirror_entry_signal(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=D("60.00"),
                take_profit_points=D("132.00"),
                risk_pct=D("10.00"),
                now_utc=clock(),
            )
            self.assertTrue(r_open["executed"])
            with self.assertRaises(ContractError) as ctx_flat:
                runner.replenish_demo_capital()
            self.assertIn(DEMO_REPLENISH_REQUIRES_FLAT_POSITIONS, str(ctx_flat.exception))
            clock.advance(2)
            runner.emergency_close_all(reason="Flatten before threshold test")

            # Drive closed losses until <= $3,500.00 (70.00%): verify post-close auto-replenisher fires automatically!
            repl_seen = False
            for _step in range(10):
                clock.advance(5)
                runner.ingest_spot_quote("NAS100", D("26800.00"), D("26801.00"), now_utc=clock())
                res_e = runner.mirror_entry_signal(
                    symbol="NAS100",
                    side="BUY",
                    stop_distance_points=D("50.00"),
                    take_profit_points=D("120.00"),
                    risk_pct=D("10.00"),
                    now_utc=clock(),
                )
                self.assertTrue(res_e["executed"], res_e)
                clock.advance(5)
                runner.ingest_spot_quote("NAS100", D("26740.00"), D("26741.00"), now_utc=clock())
                cur_s = runner.snapshot()
                if cur_s["replenishment_count"] >= 2:
                    repl_seen = True
                    self.assertEqual(cur_s["balance_usd"], "5000.00")
                    self.assertFalse(cur_s["drawdown_locked"])
                    break
            self.assertTrue(repl_seen, "Expected post-close auto-replenish at <= 70.00% ($3,500.00)")

            with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                cnt_trades = int(conn.execute("SELECT COUNT(*) FROM option_b_closed_trades").fetchone()[0])
                self.assertGreater(cnt_trades, 6)
                # Simulate crash/restart when flat balance is <= 70% ($3,450.00) -> startup auto-replenishes immediately!
                conn.execute("UPDATE option_b_meta SET last_balance_usd = '3450.00', peak_equity_usd = '5000.00' WHERE id = 1")
                conn.commit()
            restarted = OptionBPaperDemoRunner(db_path=db_path, valve_gate=_StubValveGate(allowed=True), clock=clock)
            snap_restart = restarted.snapshot()
            self.assertEqual(snap_restart["balance_usd"], "5000.00")
            self.assertFalse(snap_restart["drawdown_locked"])
            self.assertGreaterEqual(snap_restart["replenishment_count"], 3)
            self.assertEqual(_validate_doc(snap_restart, OB_SCHEMA_PATH), [])

    def test_03_option_b_http_zero_write_and_owner_replenish(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "ob.sqlite3"
            _seed_pre_u47_option_b_db(db_path)
            runner = OptionBPaperDemoRunner(db_path=db_path, valve_gate=_StubValveGate(allowed=True), clock=clock)
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                host="127.0.0.1",
                port=0,
                emergency_port=0,
                option_b_demo=runner,
                broker_router_reader=lambda: {"execution_mode": "DEMO", "live_trading_armed": False},
            )
            srv.start()
            try:
                with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                    dv0 = int(conn.execute("PRAGMA data_version").fetchone()[0])
                st_get, snap_get = _http_json(f"{srv.base_url}/api/option-b-demo", token=srv.auth_token)
                self.assertEqual(st_get, 200)
                self.assertEqual(_validate_doc(snap_get, OB_SCHEMA_PATH), [])
                with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                    self.assertEqual(int(conn.execute("PRAGMA data_version").fetchone()[0]), dv0)

                # Paired device blocked with 403
                _, cd = _http_json(f"{srv.base_url}/api/pair-code", method="POST", token=srv.auth_token, body={"ttl_seconds": 60})
                _, ex = _http_json(f"{srv.base_url}/api/pair-exchange", method="POST", body={"pair_code": cd["pair_code"]})
                st_paired, _ = _http_json(
                    f"{srv.base_url}/api/option-b-demo",
                    method="POST",
                    token=ex["session_token"],
                    body={"action": "REPLENISH_DEMO_CAPITAL"},
                )
                self.assertEqual(st_paired, 403)

                st_extra, _ = _http_json(
                    f"{srv.base_url}/api/option-b-demo",
                    method="POST",
                    token=srv.auth_token,
                    body={"action": "REPLENISH_DEMO_CAPITAL", "extra": 1},
                )
                self.assertEqual(st_extra, 400)

                st_post, post_doc = _http_json(
                    f"{srv.base_url}/api/option-b-demo",
                    method="POST",
                    token=srv.auth_token,
                    body={"action": "REPLENISH_DEMO_CAPITAL", "reason": "API top-up"},
                )
                self.assertEqual(st_post, 200)
                self.assertEqual(post_doc["snapshot"]["balance_usd"], "5000.00")
                self.assertEqual(_validate_doc(post_doc["snapshot"], OB_SCHEMA_PATH), [])
            finally:
                srv.stop()

    def test_04_parallel_tiers_70pct_replenish_all_and_http_guards(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "tiers.sqlite3"
            _seed_pre_u47_parallel_tiers_db(db_path)
            gate = load_default_forex_valve_gate(peak_equity_store=PeakEquityStore(db_path))
            eng = ParallelTierEngine(
                db_path,
                valve_gate=gate,
                demo_high_growth=DemoHighGrowthProfile(enabled=True),
                clock=clock,
            )
            snap0 = eng.snapshot()
            self.assertEqual(snap0["auto_replenish_floor_pct"], "70.00")
            self.assertTrue(snap0["auto_replenish_enabled"])
            self.assertEqual(_validate_doc(snap0, PT_SCHEMA_PATH), [])

            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                host="127.0.0.1",
                port=0,
                emergency_port=0,
                parallel_tiers=eng,
                broker_router_reader=lambda: {"execution_mode": "DEMO", "live_trading_armed": False},
            )
            srv.start()
            try:
                with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                    dv0 = int(conn.execute("PRAGMA data_version").fetchone()[0])
                st_get, get_doc = _http_json(f"{srv.base_url}/api/parallel-tiers", token=srv.auth_token)
                self.assertEqual(st_get, 200)
                self.assertEqual(get_doc, eng.snapshot())
                self.assertEqual(_validate_doc(get_doc, PT_SCHEMA_PATH), [])
                with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                    self.assertEqual(int(conn.execute("PRAGMA data_version").fetchone()[0]), dv0)

                st_unauth, _ = _http_json(f"{srv.base_url}/api/parallel-tiers", method="POST", body={"action": "REPLENISH_ALL_TIERS"})
                self.assertEqual(st_unauth, 401)

                st_all, all_doc = _http_json(
                    f"{srv.base_url}/api/parallel-tiers",
                    method="POST",
                    token=srv.auth_token,
                    body={"action": "REPLENISH_ALL_TIERS", "reason": "Deploy top-up"},
                )
                self.assertEqual(st_all, 200)
                self.assertEqual(all_doc["result"]["replenished_count"], 5)
                by_id = {t["tier_id"]: t for t in all_doc["snapshot"]["tiers"]}
                self.assertEqual(by_id["TIER_1_CURRENT"]["balance_usd"], "300000")
                self.assertEqual(by_id["TIER_2_1000"]["balance_usd"], "1000")
                self.assertEqual(by_id["TIER_3_3000"]["balance_usd"], "3000")
                self.assertEqual(by_id["TIER_4_6000"]["balance_usd"], "6000")
                self.assertEqual(by_id["TIER_5_300"]["balance_usd"], "300")
                self.assertEqual(PeakEquityStore(db_path).read_peak("tier:TIER_2_1000"), D("1000"))
                self.assertEqual(_validate_doc(all_doc["snapshot"], PT_SCHEMA_PATH), [])

                # Verify closed trades were never deleted and hash chain exists in SQLite
                with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                    closed_cnt = int(conn.execute("SELECT COUNT(*) FROM tier_closed_trades").fetchone()[0])
                    ev_rows = conn.execute("SELECT prev_sha256, event_sha256, tier_id, event_kind, trigger_source, reason, previous_balance_usd, added_usd, new_balance_usd, new_peak_equity_usd, observed_at FROM tier_replenishment_events ORDER BY seq ASC").fetchall()
                    self.assertEqual(closed_cnt, 5)
                    self.assertEqual(len(ev_rows), 5)
                    prev = "0" * 64
                    for r in ev_rows:
                        self.assertEqual(r[0], prev)
                        payload = {
                            "tier_id": r[2],
                            "event_kind": r[3],
                            "trigger": r[4],
                            "reason": r[5],
                            "previous_balance_usd": r[6],
                            "added_usd": r[7],
                            "new_balance_usd": r[8],
                            "new_peak_equity_usd": r[9],
                            "observed_at": r[10],
                            "prev_sha256": r[0],
                        }
                        exp_sha = sha256(canonical_bytes(payload)).hexdigest()
                        self.assertEqual(r[1], exp_sha)
                        prev = exp_sha

                # Toggle auto-replenish off & set custom floor 75%, push TIER_5_300 <= 210 via SQLite + trigger SET_AUTO_REPLENISH=True
                with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                    conn.execute("UPDATE tier_accounts SET balance_usd = '209.00', equity_usd = '209.00' WHERE tier_id = 'TIER_5_300'")
                    conn.commit()
                st_cfg, cfg_doc = _http_json(
                    f"{srv.base_url}/api/parallel-tiers",
                    method="POST",
                    token=srv.auth_token,
                    body={"action": "SET_AUTO_REPLENISH", "enabled": True, "floor_pct": "70.00"},
                )
                self.assertEqual(st_cfg, 200)
                by_id_after = {t["tier_id"]: t for t in cfg_doc["snapshot"]["tiers"]}
                self.assertEqual(by_id_after["TIER_5_300"]["balance_usd"], "300")
                self.assertEqual(by_id_after["TIER_5_300"]["replenishment_count"], 2)

                # Also verify startup auto-replenish on ParallelTierEngine when TIER_2_1000 is <= 70% ($690.00)
                with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                    conn.execute("UPDATE tier_accounts SET balance_usd = '690.00', equity_usd = '690.00' WHERE tier_id = 'TIER_2_1000'")
                    conn.commit()
                eng_restarted = ParallelTierEngine(
                    db_path,
                    valve_gate=load_default_forex_valve_gate(peak_equity_store=PeakEquityStore(db_path)),
                    demo_high_growth=DemoHighGrowthProfile(enabled=True),
                    clock=clock,
                )
                by_id_restart = {t["tier_id"]: t for t in eng_restarted.snapshot()["tiers"]}
                self.assertEqual(by_id_restart["TIER_2_1000"]["balance_usd"], "1000")
                self.assertGreaterEqual(by_id_restart["TIER_2_1000"]["replenishment_count"], 2)
                self.assertEqual(_validate_doc(eng_restarted.snapshot(), PT_SCHEMA_PATH), [])
            finally:
                srv.stop()

    def test_05_exclude_offline_hugosway_and_demo_baseline_reanchor(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            live_prices = {
                "NAS100": (D("26800.00"), D("26802.00")),
                "US30": (D("49000.00"), D("49004.00")),
                "SPX500": (D("7200.00"), D("7200.60")),
                "XAUUSD": (D("3650.00"), D("3650.60")),
            }
            emu_h = Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=1002903,
                quotes=dict(live_prices),
                balance=D("0.00"),
                connected=False,
                clock=clock,
            )
            emu_h.publish_market()
            emu_l = Mt5SpoolPaperTerminalEmulator(
                root / "lhfx_mt5",
                server="LHFXSA-Trade",
                login=122590,
                quotes=dict(live_prices),
                balance=D("50458.76"),
                clock=clock,
            )
            emu_l.publish_market()

            peak_store = PeakEquityStore(root / "peak.sqlite3")
            gate = load_default_forex_valve_gate(peak_equity_store=peak_store)
            oanda = _StubOandaTransport(equity="100000.00")
            env = {
                ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                ENV_MT5_TRANSPORT_MODE: TRANSPORT_SPOOL_BRIDGE,
                ENV_MT5_SPOOL_DIR: str(root),
                ENV_HUGOSWAY_MT5_LOGIN: "1002903",
                ENV_HUGOSWAY_MT5_PASSWORD: _fixture_str("hugo"),
                ENV_HUGOSWAY_MT5_SERVER: "Hugosway-Demo",
                ENV_LHFX_MT5_LOGIN: "122590",
                ENV_LHFX_MT5_SERVER: "LHFXSA-Trade",
                ENV_OANDA_PRACTICE_TOKEN: _fixture_str("oanda"),
                ENV_OANDA_PRACTICE_ACCOUNT_ID: oanda.account_id,
                "CAS_FOREX_ANTHROPIC_API_KEY": _fixture_str("claude"),
            }
            emus = {BROKER_HUGOSWAY_MT5: emu_h, BROKER_LHFX_MT5: emu_l}

            def idx_ref(syms: tuple[str, ...]) -> dict[str, dict[str, object]]:
                return {
                    s: {
                        "bid": live_prices[s][0],
                        "ask": live_prices[s][1],
                        "source_provider": "PUBLIC_US_INDEX_FEED",
                        "source_broker_id": None,
                        "is_independent_public": True,
                        "observed_at": clock().isoformat().replace("+00:00", "Z"),
                    }
                    for s in syms
                    if s in live_prices
                }

            router = DualShieldBrokerRouter(
                environ=env,
                valve_gate=gate,
                peak_equity_store=peak_store,
                index_reference_source=idx_ref,
                transport_factory=lambda bid, _m, r: Mt5SpoolBridgeTransport(
                    Path(r) / bid.lower(), sleep=emus[bid].sleep_hook, poll_interval_seconds=0.01, clock=clock
                ),
                oanda_client_factory=lambda e: OandaPracticePaperClient.from_runtime_env(e, transport=oanda, clock=clock),
                clock=clock,
            )
            router.activate_all()
            state_dir = root / "state"
            state_dir.mkdir(parents=True, exist_ok=True)
            trader = AutonomousAiTrader(
                router=router,
                model_registry=FrontierModelRegistry(environ=env, clock=clock, http_post=_open_first_choice_http(), resolve_dns=lambda _h: None),
                valve_gate=gate,
                quota_store=DailyQuotaGovernanceStore(state_dir / "quota.sqlite3"),
                peak_equity_store=peak_store,
                execution_gate=DurableModelExecutionGate(db_path=state_dir / "gate.sqlite3", clock=clock),
                aggression_dial=AggressionDialStore(state_dir / "dial.sqlite3", scope_id="dual-shield-barbell"),
                demo_high_growth=DemoHighGrowthProfile(enabled=True),
                state_dir=state_dir,
                clock=clock,
            )
            try:
                snap = trader.status_snapshot(now=clock())
                self.assertEqual(_validate_doc(snap, AI_SCHEMA_PATH), [])
                bs = snap["banked_session"]
                self.assertEqual(bs["initial_capital_usd"], "200000")
                self.assertEqual(bs["excluded_offline_demo_brokers"], [BROKER_HUGOSWAY_MT5])
                self.assertEqual(bs["deficit_to_principal_usd"], "49541.24")

                # Drop online equity <= 70% of current peak (e.g. $150,458.76 -> $102,000.00 = 32.2% DD):
                # run_cycle MUST auto-reanchor DEMO baseline cleanly without requiring manual intervento
                emu_l.balance = D("2000.00")
                emu_l.publish_market()
                clock.advance(2)
                trader.run_cycle(mt5_quotes=live_prices, fast_tick=True, now=clock())
                snap2 = trader.status_snapshot(now=clock())
                self.assertEqual(_validate_doc(snap2, AI_SCHEMA_PATH), [])
                self.assertEqual(snap2["banked_session"]["demo_baseline_reanchor_count"], 1)
                self.assertEqual(snap2["banked_session"]["demo_reanchored_baseline_usd"], "102000")
                self.assertEqual(snap2["recent_actions"][0]["kind"], "DEMO_CAPITAL_REPLENISHED")

                # Simulate external LHFX portal top-up ($2,000 -> $100,000.00) -> seamless adoption!
                emu_l.balance = D("100000.00")
                emu_l.publish_market()
                clock.advance(2)
                snap3 = trader.status_snapshot(now=clock())
                self.assertEqual(_validate_doc(snap3, AI_SCHEMA_PATH), [])
                self.assertEqual(snap3["banked_session"]["current_total_equity_usd"], "200000")
                self.assertEqual(snap3["banked_session"]["capital_status"], "AT_PRINCIPAL")

                # Verify owner HTTP /api/ai-trader-control REANCHOR_DEMO_BASELINE & SET_DEMO_AUTO_REPLENISH
                srv_t = LoopbackCockpitServer(
                    repo_root=REPO_ROOT,
                    host="127.0.0.1",
                    port=0,
                    emergency_port=0,
                    autonomous_trader=trader,
                    broker_router_reader=lambda: {"execution_mode": "DEMO", "live_trading_armed": False},
                )
                srv_t.start()
                try:
                    st_ra, doc_ra = _http_json(
                        f"{srv_t.base_url}/api/ai-trader-control",
                        method="POST",
                        token=srv_t.auth_token,
                        body={"action": "REANCHOR_DEMO_BASELINE", "reason": "Owner HTTP reanchor"},
                    )
                    self.assertEqual(st_ra, 200)
                    self.assertTrue(doc_ra["reanchored"])
                    self.assertEqual(doc_ra["new_baseline_equity_usd"], "200000")

                    st_sd, doc_sd = _http_json(
                        f"{srv_t.base_url}/api/ai-trader-control",
                        method="POST",
                        token=srv_t.auth_token,
                        body={"action": "SET_DEMO_AUTO_REPLENISH", "enabled": True, "floor_pct": "70.00"},
                    )
                    self.assertEqual(st_sd, 200)
                    self.assertTrue(doc_sd["demo_auto_replenish_enabled"])
                finally:
                    srv_t.stop()
            finally:
                trader.close()


if __name__ == "__main__":
    unittest.main()
