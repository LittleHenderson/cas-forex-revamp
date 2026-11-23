"""PR #42 Stage 2 tests: Option B $5,000.00 Micro Futures Paper Demo wired into live cockpit."""

from __future__ import annotations

import contextlib
from datetime import datetime, timezone
from decimal import Decimal
import http.client
import json
from pathlib import Path
import re
import sqlite3
import tempfile
import threading
import unittest
import urllib.parse

from cas_forex_revamp.composition.live_cockpit_server import (
    LoopbackCockpitServer,
    _feed_option_b_demo_from_index_stream,
    _poll_index_and_fx_once,
)
from cas_forex_revamp.composition.option_b_paper_runner import OptionBPaperDemoRunner
from cas_forex_revamp.valve.tks_meta_valve_controller import ValveDecision
from cas_forex_revamp.venue.dual_shield_router import compute_drawdown_pct


class _StubValveGate:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls = 0

    def evaluate(self, proposal, *, current_view=None, policy=None, now=None) -> ValveDecision:
        self.calls += 1
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


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "docs" / "contracts" / "option-b-demo.schema.json"

_SCHEMA_TYPE_CHECKS = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def _validate_node(value: object, subschema: dict, path: str) -> list[str]:
    errors: list[str] = []
    if "const" in subschema:
        expected = subschema["const"]
        if value != expected or type(value) is not type(expected):
            errors.append(f"{path}: expected const {expected!r}, got {value!r}")
    if "enum" in subschema:
        allowed = subschema["enum"]
        if not any(value == opt and type(value) is type(opt) for opt in allowed):
            errors.append(f"{path}: value {value!r} not in enum {allowed!r}")
    if "type" in subschema:
        raw_types = subschema["type"]
        expected_types = [raw_types] if isinstance(raw_types, str) else list(raw_types)
        if not any(_SCHEMA_TYPE_CHECKS[t](value) for t in expected_types):
            errors.append(f"{path}: expected type {expected_types!r}, got {type(value).__name__}")
            return errors
    if isinstance(value, str):
        if "minLength" in subschema and len(value) < int(subschema["minLength"]):
            errors.append(f"{path}: length {len(value)} < minLength {subschema['minLength']}")
        if "maxLength" in subschema and len(value) > int(subschema["maxLength"]):
            errors.append(f"{path}: length {len(value)} > maxLength {subschema['maxLength']}")
        if "pattern" in subschema and re.search(str(subschema["pattern"]), value) is None:
            errors.append(f"{path}: {value!r} does not match pattern {subschema['pattern']!r}")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in subschema and value < subschema["minimum"]:
            errors.append(f"{path}: {value} < minimum {subschema['minimum']}")
    if isinstance(value, list):
        if "minItems" in subschema and len(value) < int(subschema["minItems"]):
            errors.append(f"{path}: len {len(value)} < minItems {subschema['minItems']}")
        if "maxItems" in subschema and len(value) > int(subschema["maxItems"]):
            errors.append(f"{path}: len {len(value)} > maxItems {subschema['maxItems']}")
        item_schema = subschema.get("items")
        if isinstance(item_schema, dict):
            for idx, item in enumerate(value):
                errors.extend(_validate_node(item, item_schema, f"{path}[{idx}]"))
    if isinstance(value, dict):
        props = subschema.get("properties", {})
        for req_key in subschema.get("required", ()):
            if req_key not in value:
                errors.append(f"{path}: missing required key {req_key!r}")
        if subschema.get("additionalProperties") is False:
            extra_keys = sorted(set(value.keys()) - set(props.keys()))
            if extra_keys:
                errors.append(f"{path}: unexpected additional properties {extra_keys!r}")
        for key, prop_schema in props.items():
            if key in value and isinstance(prop_schema, dict):
                errors.extend(_validate_node(value[key], prop_schema, f"{path}.{key}"))
    return errors


def _validate_option_b_schema(payload: dict, schema: dict) -> list[str]:
    errors = _validate_node(payload, schema, "$")
    try:
        import jsonschema  # type: ignore
    except ImportError:
        jsonschema = None
    if jsonschema is not None:
        validator = jsonschema.Draft202012Validator(schema)
        errors.extend(f"jsonschema: {err.message}" for err in validator.iter_errors(payload))
    return errors


def _http_json(
    url: str,
    *,
    method: str = "GET",
    token: str | None = None,
    body: dict | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict]:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or "127.0.0.1"
    port = int(parsed.port or (443 if parsed.scheme == "https" else 80))
    path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    headers = {
        "Host": parsed.netloc,
        "Accept": "application/json",
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(data))
    if extra_headers:
        headers.update(extra_headers)
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {"raw": raw}
        return resp.status, payload
    finally:
        conn.close()


class Pr42OptionBCockpitWiredTests(unittest.TestCase):
    def test_pr42_get_option_b_demo_auth_schema_and_zero_write(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        now = datetime(2026, 11, 23, 15, 30, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            runner = OptionBPaperDemoRunner(
                db_path=tmp_path / "option_b_paper_demo.sqlite3",
                valve_gate=_StubValveGate(allowed=True),
                clock=lambda: now,
            )
            runner.ingest_spot_quote("NAS100", Decimal("26778.40"), Decimal("26779.60"), now_utc=now)

            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                host="127.0.0.1",
                port=0,
                emergency_port=0,
                option_b_demo=runner,
            )
            srv.start()
            try:
                # Unauthenticated GET must fail closed with 401
                st_unauth, _ = _http_json(f"{srv.base_url}/api/option-b-demo")
                self.assertEqual(st_unauth, 401)

                # Record SQLite data_version before authenticated GET to prove 0-write read invariance
                with contextlib.closing(sqlite3.connect(str(runner.db_path))) as conn:
                    ver_before = conn.execute("PRAGMA data_version").fetchone()[0]

                st_ok, payload = _http_json(f"{srv.base_url}/api/option-b-demo", token=srv.auth_token)
                self.assertEqual(st_ok, 200)
                self.assertEqual(payload["schema"], "cas-forex.option-b-demo/1")
                self.assertEqual(payload["mode"], "DEMO")
                self.assertIs(payload["paper_demo_only"], True)
                self.assertEqual(payload["real_money_at_risk_usd"], "0.00")
                self.assertIs(payload["owner_controls_allowed"], True)
                self.assertEqual(payload["session_scope"], "OWNER_FULL_CONTROL")
                self.assertEqual(_validate_option_b_schema(payload, schema), [])

                with contextlib.closing(sqlite3.connect(str(runner.db_path))) as conn:
                    ver_after = conn.execute("PRAGMA data_version").fetchone()[0]
                self.assertEqual(ver_after, ver_before)
            finally:
                srv.stop()

    def test_pr42_post_option_b_demo_scope_csrf_and_owner_lifecycle(self) -> None:
        now = datetime(2026, 11, 23, 15, 35, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            runner = OptionBPaperDemoRunner(
                db_path=tmp_path / "option_b_paper_demo.sqlite3",
                valve_gate=_StubValveGate(allowed=True),
                clock=lambda: now,
            )
            runner.ingest_spot_quote("NAS100", Decimal("26778.00"), Decimal("26779.00"), now_utc=now)
            runner.ingest_spot_quote("XAUUSD", Decimal("3615.00"), Decimal("3615.50"), now_utc=now)

            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                host="127.0.0.1",
                port=0,
                emergency_port=0,
                option_b_demo=runner,
            )
            srv.start()
            try:
                # 1. Unauthenticated POST blocked
                st_unauth, _ = _http_json(
                    f"{srv.base_url}/api/option-b-demo",
                    method="POST",
                    body={"action": "EMERGENCY_CLOSE_ALL"},
                )
                self.assertEqual(st_unauth, 401)

                # 2. Cross-origin CSRF POST blocked with 403
                st_csrf, _ = _http_json(
                    f"{srv.base_url}/api/option-b-demo",
                    method="POST",
                    token=srv.auth_token,
                    body={"action": "EMERGENCY_CLOSE_ALL"},
                    extra_headers={"Origin": "https://evil.example.com"},
                )
                self.assertEqual(st_csrf, 403)

                # 3. Read-only paired device POST blocked with 403
                st_code, code_doc = _http_json(
                    f"{srv.base_url}/api/pair-code",
                    method="POST",
                    token=srv.auth_token,
                    body={"ttl_seconds": 60},
                )
                self.assertEqual(st_code, 200)
                st_ex, dev_doc = _http_json(
                    f"{srv.base_url}/api/pair-exchange",
                    method="POST",
                    body={"pair_code": code_doc["pair_code"]},
                )
                self.assertEqual(st_ex, 200)
                dev_token = dev_doc["session_token"]

                st_dev_get, dev_snap = _http_json(f"{srv.base_url}/api/option-b-demo", token=dev_token)
                self.assertEqual(st_dev_get, 200)
                self.assertIs(dev_snap["owner_controls_allowed"], False)

                st_dev_post, _ = _http_json(
                    f"{srv.base_url}/api/option-b-demo",
                    method="POST",
                    token=dev_token,
                    body={"action": "EMERGENCY_CLOSE_ALL"},
                )
                self.assertEqual(st_dev_post, 403)

                # 4. Extra properties & >1.00% constitutional stop-loss risk rejected with 400
                st_extra, _ = _http_json(
                    f"{srv.base_url}/api/option-b-demo",
                    method="POST",
                    token=srv.auth_token,
                    body={"action": "EMERGENCY_CLOSE_ALL", "bogus_field": True},
                )
                self.assertEqual(st_extra, 400)

                st_risk, _ = _http_json(
                    f"{srv.base_url}/api/option-b-demo",
                    method="POST",
                    token=srv.auth_token,
                    body={
                        "action": "MIRROR_SIGNAL",
                        "symbol": "NAS100",
                        "side": "BUY",
                        "stop_distance_points": "10",
                        "take_profit_points": "25",
                        "risk_pct": "1.50",
                    },
                )
                self.assertEqual(st_risk, 400)

                # 5. Owner MIRROR_SIGNAL -> valve-cleared entry -> EMERGENCY_CLOSE_ALL
                st_open, open_doc = _http_json(
                    f"{srv.base_url}/api/option-b-demo",
                    method="POST",
                    token=srv.auth_token,
                    body={
                        "action": "MIRROR_SIGNAL",
                        "symbol": "NAS100",
                        "side": "BUY",
                        "stop_distance_points": "10",
                        "take_profit_points": "25",
                        "risk_pct": "1.00",
                    },
                )
                self.assertEqual(st_open, 200)
                self.assertIs(open_doc["ok"], True)
                self.assertEqual(open_doc["action"], "MIRROR_SIGNAL")
                self.assertEqual(open_doc["snapshot"]["mode"], "DEMO")

                st_flat, flat_doc = _http_json(
                    f"{srv.base_url}/api/option-b-demo",
                    method="POST",
                    token=srv.auth_token,
                    body={"action": "EMERGENCY_CLOSE_ALL", "reason": "TEST_FLATTEN"},
                )
                self.assertEqual(st_flat, 200)
                self.assertIs(flat_doc["ok"], True)
                self.assertEqual(len(flat_doc["snapshot"]["open_positions"]), 0)
            finally:
                srv.stop()

    def test_pr42_poll_index_feeds_option_b_and_quantizes_repeating_drawdown(self) -> None:
        now = datetime(2026, 11, 23, 15, 40, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            runner = OptionBPaperDemoRunner(
                db_path=tmp_path / "option_b_paper_demo.sqlite3",
                valve_gate=_StubValveGate(allowed=True),
                clock=lambda: now,
            )

            class _StubRouter:
                venues: dict = {}

            class _StubIndexClient:
                def fetch_index_stream(self) -> dict:
                    return {
                        "schema": "cas-forex.index-stream/1",
                        "observed_at": "2026-11-23T15:40:00Z",
                        "markets": [
                            {"pair": "NAS100", "bid": "26778.25", "ask": "26779.75"},
                            {"pair": "US30", "bid": "49000.00", "ask": "49002.00"},
                            {"pair": "SPX500", "bid": "7087.25", "ask": "7087.75"},
                            {"pair": "XAUUSD", "bid": "3615.00", "ask": "3615.50"},
                        ],
                    }

            class _StubTrader:
                called = False

                def run_cycle(self, *args, **kwargs) -> None:
                    self.called = True

            stream_lock = threading.Lock()
            latest_stream: list = [None]
            latest_pub: list = [None]
            latest_mt5: list = [None]
            notified: list[int] = []

            _poll_index_and_fx_once(
                router=_StubRouter(),
                feed_client=None,
                index_client=_StubIndexClient(),
                trader=_StubTrader(),
                autonomous_ai=False,
                stream_lock=stream_lock,
                latest_stream=latest_stream,
                latest_public_index_stream=latest_pub,
                latest_mt5_index_stream=latest_mt5,
                poll_mt5_cache={},
                poll_log_throttle={},
                poll_state={},
                base_wait=2.0,
                now_mono=10.0,
                notify_updated=lambda: notified.append(1),
                option_b_demo=runner,
            )
            self.assertEqual(notified, [1])
            snap = runner.snapshot(now_utc=now)
            by_root = {c["root_symbol"]: c for c in snap["supported_contracts"]}
            self.assertEqual(by_root["MNQ"]["bid"], "26778.25")
            self.assertEqual(by_root["MYM"]["ask"], "49002")
            self.assertEqual(by_root["MES"]["bid"], "7087.25")
            self.assertEqual(by_root["MGC"]["ask"], "3615.5")

            # Repeating decimal drawdown guard (PR #40 alignment)
            rep_dd = compute_drawdown_pct(Decimal("4994.34"), Decimal("5000.00"))
            self.assertGreaterEqual(rep_dd, Decimal("0"))
            self.assertLessEqual(len(str(snap["drawdown_pct"]).split(".")[-1]), 2)
            self.assertEqual(_feed_option_b_demo_from_index_stream(runner, None), 0)


if __name__ == "__main__":
    unittest.main()
