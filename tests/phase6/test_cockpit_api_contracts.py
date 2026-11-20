"""Contract, audit-chain, metrics, SSE dedupe, and auth/lease tests for LoopbackCockpitServer."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import http.client
import json
from pathlib import Path
import re
import socket
import sqlite3
import tempfile
import threading
import time
import unittest

from cas_forex_revamp.composition.autonomous_trader import (
    RISK_GEAR_AGGRESSIVE,
    AutonomousAiTrader,
)
from cas_forex_revamp.composition.live_cockpit_server import (
    STRICT_CSP,
    LoopbackCockpitServer,
)
from cas_forex_revamp.composition.parallel_tiers import ParallelTierEngine
from cas_forex_revamp.composition.state_store import OwnerRecoveryVerifier
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.operator.frontier_backends import (
    _SENSITIVE_KEY_WORDS,
    FrontierModelRegistry,
)
from cas_forex_revamp.treasury.profit_sweep import (
    GENESIS_AUDIT_SHA256,
    ProfitSweepVault,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.live_market_stream import MarketStreamEnvelope
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BrokerHierarchyRouter,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
)
from cas_forex_revamp.venue.external_paper_broker import OandaPracticePaperClient

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_DIR = REPO_ROOT / "docs" / "contracts"
T0 = datetime(2026, 11, 17, 14, 0, tzinfo=timezone.utc)

SUPPORTED_SCHEMA_KEYWORDS = frozenset({
    "$schema",
    "$id",
    "$defs",
    "$ref",
    "$comment",
    "title",
    "description",
    "type",
    "const",
    "enum",
    "anyOf",
    "properties",
    "additionalProperties",
    "required",
    "items",
    "maxItems",
    "minItems",
    "uniqueItems",
    "pattern",
    "format",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
})

_UTC_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$"
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def validate_contract_schema(
    value: object,
    schema: dict[str, object],
    root: dict[str, object] | None = None,
    path: str = "$",
) -> None:
    """Zero-dependency validator mirroring ui/src/wire.mjs assertSchema (24 keywords)."""
    if root is None:
        root = schema
    for kw in schema:
        if kw not in SUPPORTED_SCHEMA_KEYWORDS:
            raise ValueError(f"{path}: unsupported schema keyword {kw!r}")

    ref = schema.get("$ref")
    if isinstance(ref, str):
        if not ref.startswith("#/$defs/"):
            raise ValueError(f"{path}: unsupported $ref {ref!r}")
        def_name = ref.split("/")[-1]
        defs = root.get("$defs")
        if not isinstance(defs, dict) or def_name not in defs:
            raise ValueError(f"{path}: unresolved $ref {ref!r}")
        validate_contract_schema(value, defs[def_name], root, path)

    any_of = schema.get("anyOf")
    if isinstance(any_of, list):
        matched = False
        last_err = ""
        for choice in any_of:
            try:
                validate_contract_schema(value, choice, root, path)
                matched = True
                break
            except ValueError as exc:
                last_err = str(exc)
        if not matched:
            raise ValueError(f"{path}: did not match anyOf ({last_err})")

    if "const" in schema and value != schema["const"]:
        raise ValueError(f"{path}: expected const {schema['const']!r}, got {value!r}")

    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path}: {value!r} not in enum {schema['enum']!r}")

    expected_type = schema.get("type")
    if expected_type is not None:
        type_ok = {
            "null": value is None,
            "object": isinstance(value, dict),
            "array": isinstance(value, list),
            "string": isinstance(value, str),
            "boolean": isinstance(value, bool),
            "integer": type(value) is int,
        }.get(str(expected_type), False)
        if not type_ok:
            raise ValueError(f"{path}: expected type {expected_type!r}, got {type(value).__name__}")

    if expected_type == "object" and isinstance(value, dict):
        props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        req = schema.get("required") if isinstance(schema.get("required"), list) else []
        for req_k in req:
            if req_k not in value:
                raise ValueError(f"{path}: missing required key {req_k!r}")
        addl = schema.get("additionalProperties", True)
        for key, item_val in value.items():
            if key in props:
                validate_contract_schema(item_val, props[key], root, f"{path}.{key}")
            elif addl is False:
                raise ValueError(f"{path}: unexpected additional property {key!r}")

    if expected_type == "array" and isinstance(value, list):
        min_items = schema.get("minItems")
        max_items = schema.get("maxItems")
        if isinstance(min_items, int) and len(value) < min_items:
            raise ValueError(f"{path}: array length {len(value)} < minItems {min_items}")
        if isinstance(max_items, int) and len(value) > max_items:
            raise ValueError(f"{path}: array length {len(value)} > maxItems {max_items}")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(x, sort_keys=True) for x in value]
            if len(set(encoded)) != len(encoded):
                raise ValueError(f"{path}: duplicate array items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for idx, elem in enumerate(value):
                validate_contract_schema(elem, item_schema, root, f"{path}[{idx}]")

    if expected_type == "string" and isinstance(value, str):
        min_len = schema.get("minLength")
        max_len = schema.get("maxLength")
        if isinstance(min_len, int) and len(value) < min_len:
            raise ValueError(f"{path}: string length {len(value)} < minLength {min_len}")
        if isinstance(max_len, int) and len(value) > max_len:
            raise ValueError(f"{path}: string length {len(value)} > maxLength {max_len}")
        pat = schema.get("pattern")
        if isinstance(pat, str) and re.search(pat, value) is None:
            raise ValueError(f"{path}: {value!r} failed pattern {pat!r}")
        fmt = schema.get("format")
        if fmt is not None:
            if fmt != "date-time":
                raise ValueError(f"{path}: unsupported format {fmt!r}")
            if _UTC_TS_RE.fullmatch(value) is None:
                raise ValueError(f"{path}: invalid UTC date-time {value!r}")

    if expected_type == "integer" and type(value) is int:
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, int) and value < minimum:
            raise ValueError(f"{path}: {value} < minimum {minimum}")
        if isinstance(maximum, int) and value > maximum:
            raise ValueError(f"{path}: {value} > maximum {maximum}")


def _load_schema(name: str) -> dict[str, object]:
    return json.loads((CONTRACTS_DIR / name).read_text(encoding="utf-8"))


def _assert_no_floats_or_sensitive_keys(obj: object, path: str = "$") -> None:
    if isinstance(obj, float):
        raise ValueError(f"{path}: float value disallowed ({obj!r})")
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            for bad in _SENSITIVE_KEY_WORDS:
                if bad in kl:
                    raise ValueError(f"{path}.{k}: sensitive key word {bad!r} disallowed")
            _assert_no_floats_or_sensitive_keys(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            _assert_no_floats_or_sensitive_keys(item, f"{path}[{idx}]")


class _FakeOandaPracticeTransport:
    def __init__(self, quotes: dict[str, tuple[Decimal, Decimal]]) -> None:
        self.quotes = dict(quotes)

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float, max_bytes: int) -> bytes:
        if url.endswith("/summary"):
            return json.dumps({
                "account": {
                    "id": "101-001-1234567-001",
                    "currency": "USD",
                    "balance": "80000",
                    "NAV": "80000",
                    "unrealizedPL": "0",
                    "marginAvailable": "80000",
                    "openPositionCount": 0,
                    "lastTransactionID": "1",
                }
            }).encode("utf-8")
        if "/pricing?" in url:
            prices = []
            for sym, (bid, ask) in self.quotes.items():
                if "_" in sym or len(sym) != 6:
                    continue
                inst = f"{sym[:3]}_{sym[3:]}"
                prices.append({"instrument": inst, "bids": [{"price": str(bid)}], "asks": [{"price": str(ask)}]})
            return json.dumps({"prices": prices}).encode("utf-8")
        raise RuntimeError(f"Unexpected OANDA transport call: {method} {url}")


class TestProfitSweepAuditChain(unittest.TestCase):
    def _populate_three_events(self, db_path: Path) -> ProfitSweepVault:
        vault = ProfitSweepVault(db_path, scope_id="main", clock=lambda: T0)
        vault.record_realized_close(
            trade_id="tr-1",
            symbol="EURUSD",
            broker_id=BROKER_HUGOSWAY_MT5,
            realized_net_usd=Decimal("400.00"),
        )
        prep = vault.prepare_broker_2fa_withdrawal(
            broker_id=BROKER_HUGOSWAY_MT5,
            amount_usd=Decimal("100.00"),
            destination_bank_label="bank-chase-01",
            owner_request_id="req-2fa-1",
            reason="sweep profit",
        )
        ver = OwnerRecoveryVerifier(db_path=db_path.parent / "recovery.sqlite3", clock=lambda: T0)
        tok = ver.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
        vault.request_broker_2fa_withdrawal(
            broker_id=BROKER_HUGOSWAY_MT5,
            amount_usd=Decimal("100.00"),
            destination_bank_label="bank-chase-01",
            owner_request_id="req-2fa-1",
            reason="sweep profit",
            verifier=ver,
            recovery_token=tok,
            intent_id=prep["intent_id"],
            intent_sha256=prep["intent_sha256"],
        )
        return vault

    def _audit_rows(self, db_path: Path) -> list[sqlite3.Row]:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute("SELECT * FROM vault_audit ORDER BY seq ASC").fetchall()
        finally:
            conn.close()

    def test_empty_vault_audit_chain_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            vault = ProfitSweepVault(Path(td) / "vault.sqlite3", clock=lambda: T0)
            rep = vault.verify_audit_chain()
            self.assertEqual(
                rep,
                {
                    "valid": True,
                    "checked_rows": 0,
                    "broken_at_id": None,
                    "last_hash": GENESIS_AUDIT_SHA256,
                },
            )

    def test_valid_multi_event_and_multi_scope_shared_db(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "shared_vault.sqlite3"
            v1 = ProfitSweepVault(db, scope_id="tier:TIER_1_CURRENT", clock=lambda: T0)
            v2 = ProfitSweepVault(db, scope_id="tier:TIER_2_1000", clock=lambda: T0)
            v1.set_config(sweep_ratio=Decimal("0.50"))
            v2.record_realized_close(
                trade_id="t-2",
                symbol="NAS100",
                broker_id=BROKER_HUGOSWAY_MT5,
                realized_net_usd=Decimal("250.00"),
            )
            v1.record_realized_close(
                trade_id="t-1",
                symbol="EURUSD",
                broker_id=BROKER_LHFX_MT5,
                realized_net_usd=Decimal("120.00"),
            )
            rows = self._audit_rows(db)
            self.assertEqual(len(rows), 3)
            rep = v1.verify_audit_chain()
            self.assertEqual(rep["valid"], True)
            self.assertEqual(rep["checked_rows"], 3)
            self.assertIsNone(rep["broken_at_id"])
            self.assertEqual(rep["last_hash"], rows[-1]["entry_sha256"])
            self.assertRegex(str(rep["last_hash"]), _SHA256_RE)

    def test_detects_payload_hash_prev_and_genesis_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "vault.sqlite3"
            vault = self._populate_three_events(db)
            rows = self._audit_rows(db)
            row1_hash = str(rows[0]["entry_sha256"])

            conn = sqlite3.connect(str(db))
            conn.execute("UPDATE vault_audit SET payload_json = ? WHERE seq = 2", ('{"tampered":1}',))
            conn.commit()
            conn.close()
            rep = vault.verify_audit_chain()
            self.assertEqual(rep, {"valid": False, "checked_rows": 2, "broken_at_id": 2, "last_hash": row1_hash})

        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "vault.sqlite3"
            vault = self._populate_three_events(db)
            rows = self._audit_rows(db)
            row1_hash = str(rows[0]["entry_sha256"])

            conn = sqlite3.connect(str(db))
            conn.execute("UPDATE vault_audit SET entry_sha256 = ? WHERE seq = 2", ("f" * 64,))
            conn.commit()
            conn.close()
            rep = vault.verify_audit_chain()
            self.assertEqual(rep, {"valid": False, "checked_rows": 2, "broken_at_id": 2, "last_hash": row1_hash})

        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "vault.sqlite3"
            vault = self._populate_three_events(db)
            rows = self._audit_rows(db)
            row1_hash = str(rows[0]["entry_sha256"])

            conn = sqlite3.connect(str(db))
            conn.execute("UPDATE vault_audit SET prev_sha256 = ? WHERE seq = 2", ("e" * 64,))
            conn.commit()
            conn.close()
            rep = vault.verify_audit_chain()
            self.assertEqual(rep, {"valid": False, "checked_rows": 2, "broken_at_id": 2, "last_hash": row1_hash})

        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "vault.sqlite3"
            vault = self._populate_three_events(db)
            conn = sqlite3.connect(str(db))
            conn.execute("UPDATE vault_audit SET prev_sha256 = ? WHERE seq = 1", ("1" * 64,))
            conn.commit()
            conn.close()
            rep = vault.verify_audit_chain()
            self.assertEqual(
                rep,
                {"valid": False, "checked_rows": 1, "broken_at_id": 1, "last_hash": GENESIS_AUDIT_SHA256},
            )

    def test_detects_head_middle_tail_deletion_and_full_wipe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "vault.sqlite3"
            vault = self._populate_three_events(db)
            conn = sqlite3.connect(str(db))
            conn.execute("DELETE FROM vault_audit WHERE seq = 1")
            conn.commit()
            conn.close()
            rep = vault.verify_audit_chain()
            self.assertEqual(rep["valid"], False)
            self.assertEqual(rep["broken_at_id"], 1)
            self.assertEqual(rep["last_hash"], GENESIS_AUDIT_SHA256)

        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "vault.sqlite3"
            vault = self._populate_three_events(db)
            row1_hash = str(self._audit_rows(db)[0]["entry_sha256"])
            conn = sqlite3.connect(str(db))
            conn.execute("DELETE FROM vault_audit WHERE seq = 2")
            conn.commit()
            conn.close()
            rep = vault.verify_audit_chain()
            self.assertEqual(rep["valid"], False)
            self.assertEqual(rep["broken_at_id"], 2)
            self.assertEqual(rep["last_hash"], row1_hash)

        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "vault.sqlite3"
            vault = self._populate_three_events(db)
            row2_hash = str(self._audit_rows(db)[1]["entry_sha256"])
            conn = sqlite3.connect(str(db))
            conn.execute("DELETE FROM vault_audit WHERE seq = 3")
            conn.commit()
            conn.close()
            rep = vault.verify_audit_chain()
            self.assertEqual(rep["valid"], False)
            self.assertEqual(rep["broken_at_id"], 3)
            self.assertEqual(rep["last_hash"], row2_hash)

        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "vault.sqlite3"
            vault = self._populate_three_events(db)
            conn = sqlite3.connect(str(db))
            conn.execute("DELETE FROM vault_audit")
            conn.commit()
            conn.close()
            rep = vault.verify_audit_chain()
            self.assertEqual(rep["valid"], False)
            self.assertEqual(rep["broken_at_id"], 1)
            self.assertEqual(rep["last_hash"], GENESIS_AUDIT_SHA256)

    def test_corrupt_sqlite_file_fails_closed_in_verify_audit_chain(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "vault.sqlite3"
            vault = self._populate_three_events(db)
            db.write_bytes(b"not-a-valid-sqlite-database-header")
            rep = vault.verify_audit_chain()
            self.assertEqual(
                rep,
                {
                    "valid": False,
                    "checked_rows": 0,
                    "broken_at_id": 1,
                    "last_hash": GENESIS_AUDIT_SHA256,
                },
            )


class TestCockpitApiContractsAndSse(unittest.TestCase):
    def _http(
        self,
        srv: LoopbackCockpitServer,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> tuple[int, dict[str, str], dict[str, object] | bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", srv.bound_port, timeout=5)
        try:
            hdrs = {"Host": srv.expected_host_header}
            if headers:
                hdrs.update(headers)
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            raw = resp.read()
            resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
            self.assertNotIn("set-cookie", resp_hdrs)
            self.assertEqual(resp_hdrs.get("content-security-policy"), STRICT_CSP)
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed = raw
            return resp.status, resp_hdrs, parsed
        finally:
            conn.close()

    def _build_full_rig(self, tmp: str) -> dict[str, object]:
        root = Path(tmp)
        gate = load_default_forex_valve_gate()
        stream = MarketStreamEnvelope.from_json_bytes(
            (CONTRACTS_DIR / "initial-market-stream.json").read_bytes()
        )
        quotes = {m["pair"]: (Decimal(m["bid"]), Decimal(m["ask"])) for m in stream.to_wire_dict()["streams"]}
        quotes.update({
            "NAS100": (Decimal("20500.00"), Decimal("20502.50")),
            "US30": (Decimal("43800.00"), Decimal("43804.00")),
            "SPX500": (Decimal("6000.00"), Decimal("6000.50")),
            "XAUUSD": (Decimal("2600.00"), Decimal("2600.60")),
        })
        emus = {
            BROKER_HUGOSWAY_MT5: Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=7001234,
                quotes=quotes,
                balance=Decimal("12000"),
                leverage=500,
                clock=lambda: T0,
            ),
            BROKER_LHFX_MT5: Mt5SpoolPaperTerminalEmulator(
                root / "lhfx_mt5",
                server="LHFXSA-Trade",
                login=8005678,
                quotes=quotes,
                balance=Decimal("8000"),
                leverage=500,
                clock=lambda: T0,
            ),
        }
        emus[BROKER_HUGOSWAY_MT5].publish_market()
        emus[BROKER_LHFX_MT5].publish_market()
        oanda = _FakeOandaPracticeTransport(quotes)
        env = {
            "CAS_FOREX_MT5_TRANSPORT_MODE": "SPOOL_BRIDGE",
            "CAS_FOREX_MT5_SPOOL_DIR": str(root),
            "CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234",
            "CAS_FOREX_HUGOSWAY_MT5_PASSWORD": "demo",  # nosec B105: non-secret test placeholder
            "CAS_FOREX_LHFX_MT5_LOGIN": "8005678",
            "CAS_FOREX_OANDA_PRACTICE_TOKEN": "demo",  # nosec B105: non-secret test placeholder
            "CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID": "101-001-1234567-001",
        }
        router = DualShieldBrokerRouter(
            environ=env,
            valve_gate=gate,
            transport_factory=lambda bid, mode, r: Mt5SpoolBridgeTransport(
                Path(r) / bid.lower(),
                sleep=emus[bid].sleep_hook,
                poll_interval_seconds=0.01,
                receipt_timeout_seconds=5,
            ),
            oanda_client_factory=lambda e: OandaPracticePaperClient(environ=e, transport=oanda),
            clock=lambda: T0,
        )
        router.activate_all()
        vault = ProfitSweepVault(root / "vault.sqlite3", scope_id="main", clock=lambda: T0)
        vault.set_config(sweep_ratio=Decimal("0.50"), auto_sweep_enabled=True)
        vault.record_realized_close(
            trade_id="tr-contract-1",
            symbol="EURUSD",
            broker_id=BROKER_HUGOSWAY_MT5,
            realized_net_usd=Decimal("300.00"),
        )
        tiers = ParallelTierEngine(root / "tiers.sqlite3", valve_gate=gate, clock=lambda: T0)
        tiers.process_tick(
            quotes=quotes,
            signal={
                "symbol": "EURUSD",
                "side": "BUY",
                "stop_price": "1.09500",
                "take_profit_price": "1.11000",
                "regime": "STRONG_TREND",
            },
            now=T0,
        )
        registry = FrontierModelRegistry(environ={})
        trader = AutonomousAiTrader(
            router=router,
            model_registry=registry,
            valve_gate=gate,
            profit_vault=vault,
            parallel_tiers=tiers,
            execution_gate=DurableModelExecutionGate(root / "model_gate.sqlite3"),
            clock=lambda: T0,
        )
        return {
            "gate": gate,
            "stream": stream,
            "quotes": quotes,
            "router": router,
            "vault": vault,
            "tiers": tiers,
            "registry": registry,
            "trader": trader,
        }

    def test_all_new_and_existing_api_contracts_and_auth_matrix(self) -> None:
        health_schema = _load_schema("health.schema.json")
        treasury_schema = _load_schema("treasury.schema.json")
        tiers_schema = _load_schema("parallel-tiers.schema.json")
        routing_schema = _load_schema("broker-routing.schema.json")
        trader_schema = _load_schema("ai-trader.schema.json")

        with tempfile.TemporaryDirectory() as td:
            rig = self._build_full_rig(td)
            stream: MarketStreamEnvelope = rig["stream"]  # type: ignore[assignment]
            router: DualShieldBrokerRouter = rig["router"]  # type: ignore[assignment]
            vault: ProfitSweepVault = rig["vault"]  # type: ignore[assignment]
            tiers: ParallelTierEngine = rig["tiers"]  # type: ignore[assignment]
            registry: FrontierModelRegistry = rig["registry"]  # type: ignore[assignment]
            trader: AutonomousAiTrader = rig["trader"]  # type: ignore[assignment]

            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                market_stream_reader=stream.to_wire_dict,
                broker_router_reader=router.routing_snapshot,
                ai_model_registry=registry,
                autonomous_trader=trader,
                index_stream_reader=lambda: {
                    "schema": "cas-forex.index-stream/1",
                    "sequence": 1,
                    "observed_at": "2026-11-17T14:00:00Z",
                    "feed_mode": "TEST_INDEX_STREAM",
                    "markets": [{"pair": "NAS100", "bid": "20500.00", "ask": "20502.50"}],
                },
                profit_vault=vault,
                parallel_tiers=tiers,
            )
            srv.start()
            self.addCleanup(srv.stop)

            st, _, body = self._http(srv, "GET", "/api/health")
            self.assertEqual(st, 200)
            validate_contract_schema(body, health_schema)
            self.assertEqual(body["authenticated"], False)

            st_ck, _, _ = self._http(srv, "GET", "/api/health", headers={"Cookie": "session=invalid"})
            self.assertEqual(st_ck, 401)
            st_bad, _, _ = self._http(srv, "GET", "/api/health", headers={"Authorization": "Bearer bad-tok"})
            self.assertEqual(st_bad, 401)

            st_ok, _, body_ok = self._http(srv, "GET", "/api/health", headers=srv.auth_headers())
            self.assertEqual(st_ok, 200)
            validate_contract_schema(body_ok, health_schema)
            self.assertEqual(body_ok["authenticated"], True)

            protected = (
                "/api/audit-verify",
                "/api/metrics",
                "/api/treasury",
                "/api/parallel-tiers",
                "/api/broker-routing",
                "/api/ai-trader",
                "/api/index-stream",
            )
            for route in protected:
                s1, h1, _ = self._http(srv, "GET", route)
                self.assertEqual(s1, 401, route)
                self.assertIn("bearer", h1.get("www-authenticate", "").lower())
                s2, _, _ = self._http(srv, "GET", route, headers={"Cookie": "cockpit=1"})
                self.assertEqual(s2, 401, route)

            st, _, tres = self._http(srv, "GET", "/api/treasury", headers=srv.auth_headers())
            self.assertEqual(st, 200)
            validate_contract_schema(tres, treasury_schema)
            _assert_no_floats_or_sensitive_keys(tres)

            st, _, pts = self._http(srv, "GET", "/api/parallel-tiers", headers=srv.auth_headers())
            self.assertEqual(st, 200)
            validate_contract_schema(pts, tiers_schema)
            for tid, pts_arr in pts["growth_series"].items():
                self.assertIsInstance(pts_arr, list, tid)
                for gp in pts_arr:
                    validate_contract_schema(gp, tiers_schema["$defs"]["growthPoint"], tiers_schema)
            _assert_no_floats_or_sensitive_keys(pts)

            st, _, brk = self._http(srv, "GET", "/api/broker-routing", headers=srv.auth_headers())
            self.assertEqual(st, 200)
            validate_contract_schema(brk, routing_schema)
            _assert_no_floats_or_sensitive_keys(brk)

            st, _, ait = self._http(srv, "GET", "/api/ai-trader", headers=srv.auth_headers())
            self.assertEqual(st, 200)
            validate_contract_schema(ait, trader_schema)
            _assert_no_floats_or_sensitive_keys(ait)

            trader.set_risk_gear_mode(RISK_GEAR_AGGRESSIVE)
            st, _, ait2 = self._http(srv, "GET", "/api/ai-trader", headers=srv.auth_headers())
            self.assertEqual(st, 200)
            validate_contract_schema(ait2, trader_schema)

            st, _, idx_body = self._http(srv, "GET", "/api/index-stream", headers=srv.auth_headers())
            self.assertEqual(st, 200)
            self.assertEqual(idx_body["schema"], "cas-forex.index-stream/1")
            self.assertGreaterEqual(len(idx_body["markets"]), 1)

            st, _, av_ok = self._http(srv, "GET", "/api/audit-verify", headers=srv.auth_headers())
            self.assertEqual(st, 200)
            self.assertEqual(av_ok["valid"], True)
            self.assertEqual(av_ok["checked_rows"], 2)
            self.assertIsNone(av_ok["broken_at_id"])
            self.assertRegex(str(av_ok["last_hash"]), _SHA256_RE)
            _assert_no_floats_or_sensitive_keys(av_ok)

            conn = sqlite3.connect(str(vault.db_path))
            conn.execute("UPDATE vault_audit SET payload_json = ? WHERE seq = 2", ('{"evil":1}',))
            conn.commit()
            conn.close()

            st, _, av_bad = self._http(srv, "GET", "/api/audit-verify", headers=srv.auth_headers())
            self.assertEqual(st, 200)
            self.assertEqual(av_bad["valid"], False)
            self.assertEqual(av_bad["broken_at_id"], 2)
            self.assertNotIn(str(vault.db_path), json.dumps(av_bad))

            self._http(srv, "GET", "/api/nonexistent-route-probe", headers=srv.auth_headers())
            st, _, met1 = self._http(srv, "GET", "/api/metrics", headers=srv.auth_headers())
            self.assertEqual(st, 200)
            _assert_no_floats_or_sensitive_keys(met1)
            self.assertEqual(met1["schema"], "cas-forex.cockpit-metrics/1")
            self.assertIs(type(met1["uptime_seconds"]), int)
            self.assertGreaterEqual(met1["auth_failures_total"], 1)
            self.assertGreaterEqual(met1["route_counts"].get("__other__", 0), 1)
            self.assertEqual(met1["components"]["profit_vault"], True)
            self.assertEqual(met1["components"]["autonomous_trader"], True)
            self.assertIn("trader_summary", met1)
            self.assertIn("parallel_tiers_summary", met1)
            self.assertIn("vault_summary", met1)

            st, _, met2 = self._http(srv, "GET", "/api/metrics", headers=srv.auth_headers())
            self.assertEqual(st, 200)
            self.assertGreater(met2["requests_total"], met1["requests_total"])

    def test_unconfigured_routes_and_v1_v2_unactivated_routing_schemas(self) -> None:
        routing_schema = _load_schema("broker-routing.schema.json")
        gate = load_default_forex_valve_gate()
        v1 = BrokerHierarchyRouter(environ={}, valve_gate=gate)
        v2 = DualShieldBrokerRouter(environ={}, valve_gate=gate)

        validate_contract_schema(v1.routing_snapshot(), routing_schema)
        validate_contract_schema(v2.routing_snapshot(), routing_schema)

        srv = LoopbackCockpitServer(repo_root=REPO_ROOT, port=0)
        srv.start()
        self.addCleanup(srv.stop)

        st_av, _, _ = self._http(srv, "GET", "/api/audit-verify", headers=srv.auth_headers())
        self.assertEqual(st_av, 404)
        st_at, _, _ = self._http(srv, "GET", "/api/ai-trader", headers=srv.auth_headers())
        self.assertEqual(st_at, 404)
        st_idx, _, _ = self._http(srv, "GET", "/api/index-stream", headers=srv.auth_headers())
        self.assertEqual(st_idx, 404)
        st_met, _, met = self._http(srv, "GET", "/api/metrics", headers=srv.auth_headers())
        self.assertEqual(st_met, 200)
        self.assertEqual(met["components"]["profit_vault"], False)

    def test_commit_lease_and_epoch_rotation_contract(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            vault = ProfitSweepVault(Path(td) / "vault.sqlite3", clock=lambda: T0)
            srv = LoopbackCockpitServer(repo_root=REPO_ROOT, port=0, profit_vault=vault)
            srv.start()
            self.addCleanup(srv.stop)

            old_tok = srv.auth_token
            old_headers = {
                "Authorization": f"Bearer {old_tok}",
                "Origin": srv.base_url,
                "Content-Type": "application/json",
            }
            payload = json.dumps({"sweep_ratio": "0.40", "auto_sweep_enabled": True}).encode("utf-8")
            old_headers["Content-Length"] = str(len(payload))
            st, _, updated = self._http(srv, "POST", "/api/treasury-config", headers=old_headers, body=payload)
            self.assertEqual(st, 200)
            self.assertEqual(updated["sweep_ratio"], "0.4")

            with srv._auth_lock:
                epoch = srv._session_epoch or ""
            entered = threading.Event()
            release = threading.Event()

            def _hold_lease() -> None:
                with srv._commit_lease(old_tok, epoch, hold_lock=False):
                    entered.set()
                    release.wait(timeout=2.0)

            t = threading.Thread(target=_hold_lease, daemon=True)
            t.start()
            self.assertTrue(entered.wait(timeout=2.0))

            rotated_result: list[str] = []

            def _do_rotate() -> None:
                rotated_result.append(srv.rotate_auth_token())

            rt = threading.Thread(target=_do_rotate, daemon=True)
            rt.start()
            time.sleep(0.1)
            self.assertEqual(rotated_result, [])
            release.set()
            t.join(timeout=2.0)
            rt.join(timeout=2.0)
            self.assertEqual(len(rotated_result), 1)
            new_tok = rotated_result[0]
            self.assertNotEqual(new_tok, old_tok)
            self.assertFalse(srv._verify_commit_epoch(old_tok, epoch))

            st_old_get, _, _ = self._http(srv, "GET", "/api/metrics", headers={"Authorization": f"Bearer {old_tok}"})
            self.assertEqual(st_old_get, 401)
            st_old_post, _, _ = self._http(srv, "POST", "/api/treasury-config", headers=old_headers, body=payload)
            self.assertEqual(st_old_post, 401)

            st_new, _, _ = self._http(srv, "GET", "/api/metrics", headers={"Authorization": f"Bearer {new_tok}"})
            self.assertEqual(st_new, 200)

    def test_sse_parallel_tiers_dedupe_suppresses_unchanged_and_reemits_on_change(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rig = self._build_full_rig(td)
            stream: MarketStreamEnvelope = rig["stream"]  # type: ignore[assignment]
            tiers: ParallelTierEngine = rig["tiers"]  # type: ignore[assignment]
            quotes: dict[str, tuple[Decimal, Decimal]] = rig["quotes"]  # type: ignore[assignment]

            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                market_stream_reader=stream.to_wire_dict,
                parallel_tiers=tiers,
            )
            srv.start()
            sock = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
            try:
                req = (
                    f"GET /api/market-events HTTP/1.1\r\n"
                    f"Host: {srv.expected_host_header}\r\n"
                    f"Authorization: Bearer {srv.auth_token}\r\n"
                    f"\r\n"
                ).encode("ascii")
                sock.sendall(req)

                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = sock.recv(4096)
                    self.assertTrue(chunk, "SSE handshake closed prematurely")
                    buf += chunk
                head_raw, rest = buf.split(b"\r\n\r\n", 1)
                head_text = head_raw.decode("utf-8")
                self.assertIn("200 OK", head_text)
                self.assertIn("text/event-stream", head_text.lower())

                def _read_until(needle: bytes, timeout_s: float = 3.0) -> bytes:
                    nonlocal rest
                    deadline = time.monotonic() + timeout_s
                    while needle not in rest:
                        if time.monotonic() > deadline:
                            raise AssertionError(f"Timed out waiting for {needle!r}; got {rest!r}")
                        rest += sock.recv(8192)
                    return rest

                _read_until(b"event: parallel_tiers\n")
                self.assertEqual(rest.count(b"event: parallel_tiers\n"), 1)

                rest = b""
                srv.notify_stream_updated()
                _read_until(b"event: market\n")
                self.assertEqual(rest.count(b"event: parallel_tiers\n"), 0)

                rest = b""
                updated_quotes = dict(quotes)
                eur_bid, eur_ask = updated_quotes["EURUSD"]
                updated_quotes["EURUSD"] = (eur_bid + Decimal("0.00500"), eur_ask + Decimal("0.00500"))
                tiers.process_tick(
                    quotes=updated_quotes,
                    signal=None,
                    now=T0 + timedelta(seconds=5),
                )
                srv.notify_stream_updated()
                _read_until(b"event: parallel_tiers\n")
                self.assertGreaterEqual(rest.count(b"event: parallel_tiers\n"), 1)

                sock.close()
                time.sleep(0.05)
                st_m, _, metrics = self._http(srv, "GET", "/api/metrics", headers=srv.auth_headers())
                self.assertEqual(st_m, 200)
                self.assertGreaterEqual(metrics["sse_events_sent_total"], 3)
            finally:
                sock.close()
                srv.stop()

    def test_metrics_tracks_explainer_ask_and_tts_routes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rig = self._build_full_rig(td)
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                broker_router_reader=rig["router"].routing_snapshot,  # type: ignore[union-attr]
                ai_model_registry=rig["registry"],  # type: ignore[arg-type]
            )
            srv.start()
            self.addCleanup(srv.stop)
            hdrs = dict(srv.auth_headers())
            hdrs["Content-Type"] = "application/json"
            st1, _, _ = self._http(
                srv,
                "POST",
                "/api/explainer-ask",
                headers=hdrs,
                body=json.dumps({"question": "What mode is active?"}).encode("utf-8"),
            )
            self.assertEqual(st1, 200)
            st2, _, _ = self._http(
                srv,
                "POST",
                "/api/explainer-tts",
                headers=hdrs,
                body=json.dumps({"text": "Demo mode active."}).encode("utf-8"),
            )
            self.assertEqual(st2, 200)
            st_m, _, metrics = self._http(srv, "GET", "/api/metrics", headers=srv.auth_headers())
            self.assertEqual(st_m, 200)
            by_route = metrics["route_counts"]
            self.assertGreaterEqual(by_route.get("/api/explainer-ask", 0), 1)
            self.assertGreaterEqual(by_route.get("/api/explainer-tts", 0), 1)


    def test_ai_trader_contract_supports_pr19_profit_floor_locked_and_research_respite(self) -> None:
        trader_schema = _load_schema("ai-trader.schema.json")
        with tempfile.TemporaryDirectory() as td:
            rig = self._build_full_rig(td)
            vault: ProfitSweepVault = rig["vault"]  # type: ignore[assignment]
            vault.set_config(initial_capital_usd=Decimal("100000"))
            trader: AutonomousAiTrader = rig["trader"]  # type: ignore[assignment]
            quotes = rig["quotes"]  # type: ignore[assignment]
            trader._quota.observe_day_start(Decimal("20000"), now=T0)
            trader._quota.record_realized_trade(
                Decimal("400"), symbol="EURUSD", ticket="tr-ratchet-1", starting_equity=Decimal("20000"), now=T0
            )
            trader._quota.record_realized_trade(
                Decimal("-250"), symbol="EURUSD", ticket="tr-ratchet-2", starting_equity=Decimal("20000"), now=T0
            )
            trader.run_cycle(None, mt5_quotes=quotes, fast_tick=True, now=T0)

            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                autonomous_trader=trader,
                ai_model_registry=rig["registry"],  # type: ignore[arg-type]
                broker_router_reader=rig["router"].routing_snapshot,  # type: ignore[union-attr]
            )
            srv.start()
            self.addCleanup(srv.stop)
            st, _, ait = self._http(srv, "GET", "/api/ai-trader", headers=srv.auth_headers())
            self.assertEqual(st, 200)
            validate_contract_schema(ait, trader_schema)
            _assert_no_floats_or_sensitive_keys(ait)
            self.assertTrue(ait["respite_mode"])
            self.assertEqual(ait["operating_mode"], "RESEARCH_RESPITE")
            self.assertEqual(ait["daily_quota"]["status"], "PROFIT_FLOOR_LOCKED")
            self.assertTrue(ait["daily_quota"]["ratchet_armed"])
            self.assertEqual(ait["recent_actions"][0]["kind"], "RESEARCH_RESPITE")

    def test_hardening_duplicate_sec_fetch_site_nan_json_error_isolation_sse_and_ipv6(self) -> None:
        class _BrokenVault:
            def snapshot(self) -> dict[str, object]:
                raise sqlite3.DatabaseError("simulated corrupt vault")

        class _BrokenTiers:
            def snapshot(self) -> dict[str, object]:
                raise RuntimeError("simulated tiers outage")

        def _broken_stream() -> dict[str, object] | None:
            raise RuntimeError("simulated stream error")

        with tempfile.TemporaryDirectory() as td:
            rig = self._build_full_rig(td)
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                market_stream_reader=_broken_stream,
                index_stream_reader=_broken_stream,
                profit_vault=_BrokenVault(),
                parallel_tiers=_BrokenTiers(),
                ai_model_registry=rig["registry"],  # type: ignore[arg-type]
                broker_router_reader=rig["router"].routing_snapshot,  # type: ignore[union-attr]
            )
            srv.start()
            self.addCleanup(srv.stop)

            # 1. Duplicate Sec-Fetch-Site headers (same-origin + cross-site) MUST be rejected with 403
            with socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5) as sock:
                raw_req = (
                    f"GET /api/metrics HTTP/1.1\r\n"
                    f"Host: {srv.expected_host_header}\r\n"
                    f"Authorization: Bearer {srv.auth_token}\r\n"
                    f"Sec-Fetch-Site: same-origin\r\n"
                    f"Sec-Fetch-Site: cross-site\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii")
                sock.sendall(raw_req)
                chunks: list[bytes] = []
                while True:
                    buf = sock.recv(4096)
                    if not buf:
                        break
                    chunks.append(buf)
                resp_text = b"".join(chunks).decode("utf-8", errors="replace")
            self.assertTrue(resp_text.startswith("HTTP/1.1 403 "), msg=resp_text[:120])

            # 2. Non-finite JSON constants (NaN / Infinity) rejected with 400
            for bad_body in (
                b'{"model_id": "claude-fable-5.2", "x": NaN}',
                b'{"model_id": "claude-fable-5.2", "x": Infinity}',
            ):
                st_bad, _, bad_resp = self._http(
                    srv,
                    "POST",
                    "/api/select-ai-model",
                    headers={**srv.auth_headers(), "Content-Type": "application/json"},
                    body=bad_body,
                )
                self.assertEqual(st_bad, 400)
                self.assertIn("non-finite", str(bad_resp["error"]).lower())  # type: ignore[index]

            # 3. Failing backend/DB snapshots return clean HTTP 500 JSON instead of dropping connection
            for err_route in ("/api/market-stream", "/api/treasury", "/api/parallel-tiers", "/api/index-stream"):
                st_err, _, err_json = self._http(srv, "GET", err_route, headers=srv.auth_headers())
                self.assertEqual(st_err, 500, msg=f"route {err_route} returned {st_err}")
                self.assertIn("error", err_json)  # type: ignore[operator]

            # 4. Failing snapshot sources inside /api/market-events emit controlled error events without dropping SSE
            conn = http.client.HTTPConnection("127.0.0.1", srv.bound_port, timeout=5)
            try:
                conn.request("GET", "/api/market-events", headers={"Host": srv.expected_host_header, **srv.auth_headers()})
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                sse_lines: list[str] = []
                deadline = time.monotonic() + 3.0
                while time.monotonic() < deadline and len(sse_lines) < 30:
                    line = resp.fp.readline().decode("utf-8", errors="replace")
                    if not line:
                        break
                    sse_lines.append(line)
                    if any("event: ai_models" in l for l in sse_lines) and any("event: error" in l for l in sse_lines):
                        break
                joined_sse = "".join(sse_lines)
                self.assertIn("event: error", joined_sse)
                self.assertIn("event: ai_models", joined_sse)
            finally:
                conn.close()

            # 5. IPv6 loopback (::1) binds and serves /api/health cleanly
            srv6 = LoopbackCockpitServer(repo_root=REPO_ROOT, host="::1", port=0)
            srv6.start()
            self.addCleanup(srv6.stop)
            conn6 = http.client.HTTPConnection("::1", srv6.bound_port, timeout=5)
            try:
                conn6.request("GET", "/api/health", headers={"Host": srv6.expected_host_header})
                r6 = conn6.getresponse()
                self.assertEqual(r6.status, 200)
                d6 = json.loads(r6.read().decode("utf-8"))
                self.assertEqual(d6["status"], "OK")
            finally:
                conn6.close()


if __name__ == "__main__":
    unittest.main()
