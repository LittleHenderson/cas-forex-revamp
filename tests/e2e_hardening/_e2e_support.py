"""Shared opaque-box fixtures, loopback HTTP helpers, and M1/M2/M3 integration gate for E2E hardening tests."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import gc
import tempfile
from typing import Iterator
from decimal import Decimal
from hashlib import sha256
import http.client
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import unittest
import urllib.parse

from cas_forex_revamp.composition.autonomous_trader import AutonomousAiTrader
from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer
from cas_forex_revamp.composition.continuous_driver import SyntheticClock, _assemble, _control
from cas_forex_revamp.composition.read_service import DecisionReadService
from cas_forex_revamp.composition.state_store import OwnerRecoveryVerifier
from cas_forex_revamp.composition.synthetic_fixture import continuous_a_fixture
from cas_forex_revamp.composition.ui_service import ScopedUIService
from cas_forex_revamp.contracts import ActionKind, ControlKind, Side
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    ForexMetaValveGate,
    PeakEquityStore,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.dual_shield_router import (
    DualShieldBrokerRouter,
    OandaQuoteTruthOracle,
)
from cas_forex_revamp.venue.external_paper_broker import OandaPracticePaperClient
from cas_forex_revamp.venue.live_market_stream import MarketStreamEnvelope
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    OrderIntent,
)

D = Decimal
REPO_ROOT = Path(__file__).resolve().parents[2]
T0 = datetime(2026, 11, 18, 13, 0, 0, tzinfo=timezone.utc)

# Non-secret synthetic test credentials (never real keys/tokens/passwords)
SYNTH_API_KEY = "demo-synth-" + "key-01"  # nosec B105: synthetic non-secret E2E test placeholder
SYNTH_OANDA_TOKEN = "demo-oanda-" + "tok-01"  # nosec B105: synthetic non-secret E2E test placeholder
SYNTH_OANDA_ACCOUNT = "101-001-0000000-001"
SYNTH_MT5_PASS = "Demo-Synth-" + "Pass-01"  # nosec B105: synthetic non-secret E2E test placeholder

QUOTES_20: dict[str, tuple[Decimal, Decimal]] = {
    "NAS100": (D("20500.00"), D("20502.50")),
    "US30": (D("43800.00"), D("43804.00")),
    "SPX500": (D("5920.00"), D("5920.75")),
    "XAUUSD": (D("2640.00"), D("2640.40")),
    "EURUSD": (D("1.10000"), D("1.10010")),
    "GBPUSD": (D("1.27000"), D("1.27012")),
    "USDJPY": (D("150.000"), D("150.012")),
    "USDCHF": (D("0.88000"), D("0.88010")),
    "AUDUSD": (D("0.65000"), D("0.65010")),
    "USDCAD": (D("1.36000"), D("1.36012")),
    "NZDUSD": (D("0.60000"), D("0.60010")),
    "EURGBP": (D("0.86600"), D("0.86612")),
    "EURJPY": (D("165.000"), D("165.015")),
    "GBPJPY": (D("190.500"), D("190.520")),
    "EURCHF": (D("0.96800"), D("0.96812")),
    "EURAUD": (D("1.69200"), D("1.69220")),
    "EURCAD": (D("1.49600"), D("1.49615")),
    "AUDJPY": (D("97.500"), D("97.512")),
    "CHFJPY": (D("170.400"), D("170.420")),
    "CADJPY": (D("110.300"), D("110.312")),
}


def is_integrated_mode() -> bool:
    return os.environ.get("CAS_FOREX_E2E_REQUIRE_INTEGRATED") == "1"


def require_or_skip_unmerged(test_case: unittest.TestCase, feature_desc: str) -> None:
    """Enforce hard-fail when CAS_FOREX_E2E_REQUIRE_INTEGRATED=1; skip cleanly on pre-merge main."""
    if is_integrated_mode():
        test_case.fail(f"M4 INTEGRATED GATE FAILURE: missing or broken contract -> {feature_desc}")
    test_case.skipTest(f"Awaiting M1/M2/M3 merge in M4: {feature_desc}")


def resolve_node_bin() -> str | None:
    """Resolve Node.js binary via GATE_NODE_BIN, PATH, or air-gapped runtime tree."""
    gate_node = os.environ.get("GATE_NODE_BIN", "").strip()
    if gate_node and Path(gate_node).is_file():
        return gate_node
    which_node = shutil.which("node")
    if which_node:
        return which_node
    for anc in (REPO_ROOT, *REPO_ROOT.parents):
        cand = anc / "runtime" / "node" / "bin" / "node"
        if cand.is_file():
            return str(cand)
    return None


def clean_demo_environ(**overrides: str) -> dict[str, str]:
    env = {"CAS_FOREX_EXECUTION_MODE": "DEMO"}
    env.update(overrides)
    return env


def stub_frontier_http_post(
    url: str,
    headers: dict[str, str],
    body: bytes,
    timeout: float,
    max_bytes: int,
) -> tuple[int, bytes]:
    """In-process HTTP transport stub for FrontierModelRegistry (zero sockets)."""
    del headers, body, timeout, max_bytes
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    answer_payload = json.dumps({"answer": "DEMO read-only stub response."})
    if "anthropic" in host:
        return 200, json.dumps({
            "content": [{"type": "text", "text": answer_payload}],
            "usage": {"output_tokens": 12},
        }).encode("utf-8")
    if "googleapis" in host:
        return 200, json.dumps({
            "candidates": [{"content": {"parts": [{"text": answer_payload}]}}],
            "usageMetadata": {"candidatesTokenCount": 12},
        }).encode("utf-8")
    if "openai" in host or "deepseek" in host:
        return 200, json.dumps({
            "choices": [{"message": {"content": answer_payload}}],
            "usage": {"completion_tokens": 12},
        }).encode("utf-8")
    return 200, json.dumps({
        "message": {"content": answer_payload},
        "eval_count": 12,
    }).encode("utf-8")


class SteppingClock:
    def __init__(self, start: datetime = T0, step: timedelta = timedelta(milliseconds=50)) -> None:
        self.now = start
        self._step = step

    def __call__(self) -> datetime:
        current = self.now
        self.now = self.now + self._step
        return current


def build_valve_proposal(
    *,
    order_id: str = "ord-e2e-1",
    action_ref: str = "act-e2e-1",
    kind: ActionKind = ActionKind.OPEN,
    symbol: str = "EURUSD",
    side: Side = Side.BUY,
    quantity: Decimal = D("10000"),
    limit_price: Decimal | None = D("1.10010"),
    stop_price: Decimal | None = D("1.09500"),
    take_profit_price: Decimal | None = D("1.11000"),
    target_id: str | None = None,
    reason: str = "ID=0act-e2e-1 Strong trend alignment",
    observed_at: datetime = T0,
    valid_until: datetime | None = None,
    evidence_ids: tuple[str, ...] = ("ev-quote-1",),
    facts: tuple[object, ...] = (),
) -> SimpleNamespace:
    exp = valid_until if valid_until is not None else (observed_at + timedelta(minutes=5))
    intent = SimpleNamespace(
        intent_id=order_id,
        action_ref=action_ref,
        kind=kind,
        instrument_id=symbol,
        quantity=quantity,
        side=side,
        stop_price=stop_price,
        limit_price=limit_price,
        take_profit_price=take_profit_price,
        target_id=target_id,
    )
    request = SimpleNamespace(
        request_id=f"req-{order_id}",
        facts=tuple(facts),
        evidence=tuple(SimpleNamespace(evidence_id=eid) for eid in evidence_ids),
        state=SimpleNamespace(observed_at=observed_at, valid_until=exp),
    )
    selection = SimpleNamespace(
        evidence_ids=evidence_ids,
        reason=reason,
        selected_action_ref=action_ref,
    )
    return SimpleNamespace(
        request=request,
        result=SimpleNamespace(selection=selection),
        intent=intent,
    )


def default_view(
    *,
    balance: str = "100000",
    equity: str = "100000",
    available_margin: str = "90000",
    bid: str = "1.10000",
    ask: str = "1.10010",
) -> dict[str, str]:
    return {
        "balance": balance,
        "equity": equity,
        "available_margin": available_margin,
        "position_inventory": "[]",
        "bid": bid,
        "ask": ask,
    }


def default_policy(
    *,
    new_risk: str = "ALLOWED",
    management: str = "ALLOWED",
    max_qty: str = "500000",
) -> dict[str, str]:
    return {
        "new_risk_permission": new_risk,
        "management_permission": management,
        "max_entry_quantity": max_qty,
    }


class StubOandaTransport:
    """In-process OANDA v20 practice stub enforcing api-fxpractice.oanda.com host."""

    def __init__(self, quotes: dict[str, tuple[Decimal, Decimal]] | None = None, *, nav: str = "80000") -> None:
        self.quotes = dict(quotes or QUOTES_20)
        self.nav = nav
        self.calls: list[tuple[str, str]] = []
        self.orders: list[dict[str, object]] = []

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float, max_bytes: int) -> bytes:
        self.calls.append((method, url))
        if urllib.parse.urlsplit(url).hostname != "api-fxpractice.oanda.com":
            raise RuntimeError(f"Non-practice OANDA host forbidden in E2E: {url}")
        if url.endswith("/summary"):
            return json.dumps({
                "account": {
                    "id": SYNTH_OANDA_ACCOUNT,
                    "currency": "USD",
                    "balance": self.nav,
                    "NAV": self.nav,
                    "unrealizedPL": "0",
                    "marginAvailable": self.nav,
                    "openPositionCount": len(self.orders),
                    "lastTransactionID": "1",
                }
            }).encode("utf-8")
        if "/pricing?" in url:
            insts = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["instruments"][0].split(",")
            prices = []
            for inst in insts:
                bid, ask = self.quotes[inst.replace("_", "")]
                prices.append({"instrument": inst, "bids": [{"price": str(bid)}], "asks": [{"price": str(ask)}]})
            return json.dumps({"prices": prices}).encode("utf-8")
        if method == "POST" and url.endswith("/orders"):
            order = json.loads((body or b"{}").decode("utf-8"))["order"]
            self.orders.append(order)
            bid, ask = self.quotes[order["instrument"].replace("_", "")]
            fill_px = ask if not str(order["units"]).startswith("-") else bid
            return json.dumps({
                "orderCreateTransaction": {"id": "101", "clientExtensions": order.get("clientExtensions", {})},
                "orderFillTransaction": {
                    "id": "102",
                    "instrument": order["instrument"],
                    "units": order["units"],
                    "price": str(fill_px),
                    "clientExtensions": order.get("clientExtensions", {}),
                },
                "lastTransactionID": "102",
            }).encode("utf-8")
        if method == "GET" and url.endswith("/openTrades"):
            trades = []
            for idx, o in enumerate(self.orders, start=1):
                if "instrument" in o:
                    sl_p = (o.get("stopLossOnFill") or {}).get("price")
                    trades.append({
                        "id": str(idx),
                        "instrument": o["instrument"],
                        "currentUnits": str(o["units"]),
                        "price": "1.10010",
                        "unrealizedPL": "0.00",
                        "state": "OPEN",
                        **({"stopLossOrder": {"price": str(sl_p)}} if sl_p else {}),
                    })
            return json.dumps({"trades": trades, "lastTransactionID": "102"}).encode("utf-8")
        if method == "PUT" and "/trades/" in url:
            amend = json.loads((body or b"{}").decode("utf-8"))
            self.orders.append(amend)
            tid_e = url.split("/")[-2]
            sl_b = amend.get("stopLoss") or {}
            return json.dumps({
                "stopLossOrderTransaction": {
                    "id": "103",
                    "tradeID": tid_e,
                    "price": str(sl_b.get("price", "1.09800")),
                    "clientExtensions": sl_b.get("clientExtensions", {}),
                },
                "lastTransactionID": "103",
            }).encode("utf-8")
        raise RuntimeError(f"Unexpected OANDA stub request: {method} {url}")


class DualBrokerTestRig:
    """Self-contained DEMO spool + OANDA practice test rig inside a temp dir."""

    def __init__(self, tmp_dir: str | Path, *, gate: ForexMetaValveGate | None = None) -> None:
        self.root = Path(tmp_dir)
        self.clock = SteppingClock()
        self.gate = gate or load_default_forex_valve_gate()
        self.emus = {
            BROKER_HUGOSWAY_MT5: Mt5SpoolPaperTerminalEmulator(
                self.root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=7001234,
                quotes=QUOTES_20,
                balance=D("12000"),
                trade_mode="DEMO",
            ),
            BROKER_LHFX_MT5: Mt5SpoolPaperTerminalEmulator(
                self.root / "lhfx_mt5",
                server="LHFXSA-Trade",
                login=8005678,
                quotes=QUOTES_20,
                balance=D("8000"),
                trade_mode="DEMO",
            ),
        }
        for emu in self.emus.values():
            emu.publish_market()
        self.oanda = StubOandaTransport(QUOTES_20)

    def environ(self, **extra: str) -> dict[str, str]:
        env = clean_demo_environ(
            CAS_FOREX_MT5_TRANSPORT_MODE="SPOOL_BRIDGE",
            CAS_FOREX_MT5_SPOOL_DIR=str(self.root),
            CAS_FOREX_HUGOSWAY_MT5_LOGIN="7001234",
            CAS_FOREX_LHFX_MT5_LOGIN="8005678",
            CAS_FOREX_OANDA_PRACTICE_TOKEN=SYNTH_OANDA_TOKEN,
            CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID=SYNTH_OANDA_ACCOUNT,
        )
        env.update(extra)
        return env

    def transport_factory(self, broker_id: str, _mode: str, root: Path) -> Mt5SpoolBridgeTransport:
        return Mt5SpoolBridgeTransport(
            Path(root) / broker_id.lower(),
            sleep=self.emus[broker_id].sleep_hook,
            poll_interval_seconds=0.01,
            receipt_timeout_seconds=5,
        )

    def oanda_factory(self, env: dict[str, str]) -> OandaPracticePaperClient:
        return OandaPracticePaperClient(environ=env, transport=self.oanda)

    def dual_router(self, **kw) -> DualShieldBrokerRouter:
        env = self.environ()
        return DualShieldBrokerRouter(
            environ=env,
            valve_gate=self.gate,
            transport_factory=self.transport_factory,
            oanda_client_factory=self.oanda_factory,
            clock=self.clock,
            **kw,
        )


def build_scoped_ui_service(root: Path, *, clock: SteppingClock | None = None) -> ScopedUIService:
    """Create a real ScopedUIService backed by continuous_a_fixture and initial-cockpit contracts."""
    root.mkdir(parents=True, exist_ok=True)
    fixture = continuous_a_fixture()
    clk = SyntheticClock(fixture.started_at)
    app, owner, journal = _assemble(root, fixture.scope, clk)
    journal.initialize(create=True)
    app.venue.initialize(
        fixture.scope.key,
        opening_balance=fixture.opening_balance,
        instruments=fixture.instruments,
        now=clk(),
        scenario=fixture.venue_scenario,
    )
    app.core.initialize(create=True)
    clk.now = fixture.market[0].available_at
    app.wiring.advance_market(fixture.market[0])
    _control(app, owner, journal, clk, ControlKind.STOP_AUTOMATION, "e2e-init-stop")
    schema = (REPO_ROOT / "docs/contracts/decision-read.schema.json").read_bytes()
    reader = DecisionReadService(
        scope=fixture.scope,
        core=app.core,
        venue=app.venue,
        journal=journal,
        clock=clk,
        schema_bytes=schema,
        schema_sha256=sha256(schema).hexdigest(),
        instruments=fixture.instruments,
    )
    return ScopedUIService(app=app, owner=owner, journal=journal, reader=reader, clock=clk)


def loopback_http_request(
    server: LoopbackCockpitServer,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    max_read: int = 262144,
) -> tuple[int, dict[str, str], bytes]:
    """Execute an opaque-box loopback HTTP call via http.client (zero urllib B310)."""
    conn = http.client.HTTPConnection("127.0.0.1", server.bound_port, timeout=5)
    try:
        hdrs = dict(headers or {})
        if "Host" not in hdrs:
            hdrs["Host"] = server.expected_host_header
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read(max_read)
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
    finally:
        conn.close()


@contextmanager
def safe_temp_dir() -> Iterator[Path]:
    """Temporary directory wrapper that triggers GC before cleanup for Windows SQLite WAL handles."""
    td = tempfile.TemporaryDirectory(ignore_cleanup_errors=(os.name == "nt"))
    try:
        yield Path(td.name)
    finally:
        gc.collect()
        td.cleanup()
