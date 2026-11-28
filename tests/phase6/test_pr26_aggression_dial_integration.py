"""PR #26 Integration Tests: Master & 5-Tier Trading Aggression Dial (20..100 bps) + AI Discretion.

Verifies:
1. GET / POST /api/aggression-dial wire contracts, JSON Schema compliance across
   aggression-dial.schema.json / ai-trader.schema.json / parallel-tiers.schema.json,
   and strict 403 rejection on paired DEVICE_READ_AND_EXPLAINER tokens.
2. LIVE mode >= 80 bps (0.80%..1.00%) HighRiskConfirmationRequiredError -> HTTP 409 Conflict
   gate (anti-downgrade against client body spoofing) and 200 OK when high_risk_confirmed=True.
3. Strict 0-SQLite-write invariant (PRAGMA data_version) across GET /api/aggression-dial,
   GET /api/ai-trader, GET /api/parallel-tiers, status_snapshot(), and SSE event: aggression_dial.
4. ParallelTierEngine ($300k, $6k, $3k, $1k, $300) independent per-tier risk_pct (0.20%..1.00%),
   max_open_trades (1..8), min_signal_prob (0.55..0.78), proportional session_goal_usd /
   soft_goal_usd / daily_loss_brake_usd, and race presets (SYNC_ALL_TO_MASTER,
   STAGGER_SAFE_TO_EXTREME, ALL_BALANCED).
5. AutonomousAiTrader Master Dial sizing, bidirectional AI Discretion (UP in TREND_IGNITION /
   STRONG_TREND within ceiling <= 1.00%, DOWN in CHOP_RANGE / losses / drawdown), Manual Lock,
   max_open_trades cap, min_signal_prob filter, session goal / loss brake, and CLI wiring.
"""

from __future__ import annotations

import ast
from contextlib import closing, redirect_stdout
import dataclasses
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import http.client
import io
import json
from pathlib import Path
import socket
import sqlite3
import tempfile
import time
import unittest
from unittest import mock
import urllib.parse

from cas_forex_revamp.composition.autonomous_trader import AutonomousAiTrader
from cas_forex_revamp.composition.live_cockpit_server import (
    LoopbackCockpitServer,
    run_cockpit_cli,
)
from cas_forex_revamp.composition.parallel_tiers import ParallelTierEngine
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.treasury.profit_sweep import ProfitSweepVault
from cas_forex_revamp.valve.aggression_dial import (
    ACCESS_MODE_DEVICE_READ_AND_EXPLAINER,
    ACCESS_MODE_OWNER_FULL_CONTROL,
    AggressionDialStore,
    PRESET_ALL_BALANCED,
    PRESET_STAGGER_SAFE_TO_EXTREME,
    PRESET_SYNC_ALL_TO_MASTER,
)
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    ForexMetaValveGate,
    PeakEquityStore,
    ValveDecision,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.external_paper_broker import OandaPracticePaperClient
from cas_forex_revamp.venue.live_market_stream import MarketStreamEnvelope
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
)
from tests.phase6.test_cockpit_api_contracts import (
    _assert_no_floats_or_sensitive_keys,
    validate_contract_schema,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_DIR = REPO_ROOT / "docs" / "contracts"
T0 = datetime(2026, 11, 20, 14, 0, 0, tzinfo=timezone.utc)
D = Decimal

BASE_QUOTES: dict[str, tuple[Decimal, Decimal]] = {
    "NAS100": (D("20500.00"), D("20502.00")),
    "US30": (D("43800.00"), D("43804.00")),
    "SPX500": (D("6000.00"), D("6000.50")),
    "XAUUSD": (D("2600.00"), D("2600.50")),
    "EURUSD": (D("1.10000"), D("1.10010")),
    "GBPUSD": (D("1.27000"), D("1.27012")),
    "USDJPY": (D("150.000"), D("150.012")),
    "USDCHF": (D("0.88000"), D("0.88010")),
    "AUDUSD": (D("0.65000"), D("0.65010")),
    "USDCAD": (D("1.36000"), D("1.36012")),
}


class _StepClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        self.now = self.now + timedelta(milliseconds=25)
        return self.now


class _FakeOandaPractice:
    def __init__(self, quotes: dict[str, tuple[Decimal, Decimal]], nav_usd: str = "240000") -> None:
        self.quotes = dict(quotes)
        self.nav_usd = nav_usd

    def __call__(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
        max_bytes: int,
    ) -> bytes:
        if urllib.parse.urlsplit(url).hostname != "api-fxpractice.oanda.com":
            raise RuntimeError("Unexpected non-practice OANDA host")
        if url.endswith("/summary"):
            return json.dumps({
                "account": {
                    "id": "101-001-1234567-001",
                    "currency": "USD",
                    "balance": self.nav_usd,
                    "NAV": self.nav_usd,
                    "unrealizedPL": "0",
                    "marginAvailable": self.nav_usd,
                    "openPositionCount": 0,
                    "lastTransactionID": "1",
                }
            }).encode("utf-8")
        if "/pricing?" in url:
            prices = []
            for sym, (bid, ask) in self.quotes.items():
                if len(sym) == 6 and "_" not in sym:
                    inst = f"{sym[:3]}_{sym[3:]}"
                    prices.append({
                        "instrument": inst,
                        "bids": [{"price": str(bid)}],
                        "asks": [{"price": str(ask)}],
                    })
            return json.dumps({"prices": prices}).encode("utf-8")
        raise RuntimeError(f"Unexpected OANDA transport call: {method} {url}")


class _AcceptingAnthropicHttp:
    """Offline deterministic Anthropic JSON-schema responder selecting options[0]."""

    def __call__(
        self,
        url: str,
        headers: dict[str, str],
        body: bytes,
        timeout: float,
        max_bytes: int,
    ) -> tuple[int, bytes]:
        req = json.loads(body.decode("utf-8"))
        user_doc = json.loads(req["messages"][0]["content"])
        action_ref = user_doc["options"][0]["action_ref"]
        ev_ids = [e["evidence_id"] for e in user_doc.get("evidence", ())[:1]] or ["ev-1"]
        sel = {
            "request_id": user_doc["request_id"],
            "opportunity_set_id": user_doc["opportunity_set_id"],
            "source_state_id": user_doc["state"]["state_id"],
            "selected_action_ref": action_ref,
            "reason": f"ID=0{action_ref} trend setup verified",
            "evidence_ids": ev_ids,
        }
        resp = {
            "content": [{"type": "text", "text": json.dumps(sel)}],
            "usage": {"output_tokens": 48},
        }
        return 200, json.dumps(resp).encode("utf-8")


class _FixedScoreValveGate(ForexMetaValveGate):
    """Wraps ForexMetaValveGate with a controllable mlp_score to test 0.55..0.78 prob cutoffs."""

    def __init__(self, inner: ForexMetaValveGate, *, forced_score: float) -> None:
        super().__init__(
            controller=inner.controller,
            peak_equity_store=inner.peak_equity_store,
            max_drawdown_pct=inner.max_drawdown_pct,
        )
        self.forced_score = forced_score

    def evaluate(
        self,
        proposal: object,
        *,
        current_view: object = None,
        policy: object = None,
        now: datetime | None = None,
    ) -> ValveDecision:
        with mock.patch.object(self.controller, "forward", return_value=float(self.forced_score)):
            return super().evaluate(proposal, current_view=current_view, policy=policy, now=now)


def _load_schema(name: str) -> dict[str, object]:
    return json.loads((CONTRACTS_DIR / name).read_text(encoding="utf-8"))


class Pr26AggressionDialIntegrationTests(unittest.TestCase):
    def _http_json(
        self,
        srv: LoopbackCockpitServer,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body_obj: dict[str, object] | None = None,
    ) -> tuple[int, dict[str, object]]:
        req_headers = {"Host": srv.expected_host_header}
        if method == "POST":
            req_headers["Origin"] = srv.base_url
            req_headers["Content-Type"] = "application/json"
        if headers:
            req_headers.update(headers)
        raw_body: bytes | None = None
        if body_obj is not None:
            raw_body = json.dumps(body_obj).encode("utf-8")
            req_headers["Content-Length"] = str(len(raw_body))
        elif method == "POST":
            raw_body = b"{}"
            req_headers["Content-Length"] = "2"

        conn = http.client.HTTPConnection("127.0.0.1", srv.bound_port, timeout=5.0)
        try:
            conn.request(method, path, body=raw_body, headers=req_headers)
            resp = conn.getresponse()
            data = resp.read().decode("utf-8")
            parsed = json.loads(data) if data.strip() else {}
            return int(resp.status), parsed
        finally:
            conn.close()

    def _build_300k_rig(
        self,
        tmp_dir: str,
        *,
        forced_valve_score: float | None = None,
        quota_mode: str = "PCT",
    ) -> dict[str, object]:
        root = Path(tmp_dir)
        clock = _StepClock()
        base_gate = load_default_forex_valve_gate(
            peak_equity_store=PeakEquityStore(root / "peak.sqlite3"),
        )
        gate: ForexMetaValveGate = (
            _FixedScoreValveGate(base_gate, forced_score=forced_valve_score)
            if forced_valve_score is not None
            else base_gate
        )
        emus = {
            BROKER_HUGOSWAY_MT5: Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=7001234,
                quotes=BASE_QUOTES,
                balance=D("36000.00"),
                leverage=500,
                clock=clock,
            ),
            BROKER_LHFX_MT5: Mt5SpoolPaperTerminalEmulator(
                root / "lhfx_mt5",
                server="LHFXSA-Trade",
                login=8005678,
                quotes=BASE_QUOTES,
                balance=D("24000.00"),
                leverage=500,
                clock=clock,
            ),
        }
        emus[BROKER_HUGOSWAY_MT5].publish_market()
        emus[BROKER_LHFX_MT5].publish_market()
        oanda = _FakeOandaPractice(BASE_QUOTES, nav_usd="240000")
        placeholder = "demo"
        router_env = {
            "CAS_FOREX_MT5_TRANSPORT_MODE": "SPOOL_BRIDGE",
            "CAS_FOREX_MT5_SPOOL_DIR": str(root),
            "CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234",
            "CAS_FOREX_HUGOSWAY_MT5_PASSWORD": placeholder,
            "CAS_FOREX_LHFX_MT5_LOGIN": "8005678",
            "CAS_FOREX_OANDA_PRACTICE_TOKEN": placeholder,
            "CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID": "101-001-1234567-001",
        }
        router = DualShieldBrokerRouter(
            environ=router_env,
            valve_gate=gate,
            peak_equity_store=gate.peak_equity_store,
            transport_factory=lambda bid, _m, r: Mt5SpoolBridgeTransport(
                Path(r) / bid.lower(),
                sleep=emus[bid].sleep_hook,
                poll_interval_seconds=0.01,
                receipt_timeout_seconds=5,
                clock=clock,
            ),
            oanda_client_factory=lambda e: OandaPracticePaperClient(environ=e, transport=oanda),
            clock=clock,
        )
        router.activate_all()

        dial = AggressionDialStore(
            root / "aggression_dial.sqlite3",
            scope_id="dual-shield-barbell",
            now_fn=clock,
        )
        vault = ProfitSweepVault(root / "vault.sqlite3", scope_id="main", clock=clock)
        tiers = ParallelTierEngine(
            root / "tiers.sqlite3",
            valve_gate=gate,
            aggression_dial=dial,
            clock=clock,
        )
        ai_env = {
            "CAS_FOREX_AI_MODEL": "claude-fable-5.2",
            "CAS_FOREX_ANTHROPIC_API_KEY": "u" * 16,
            "CAS_FOREX_GEMINI_DECISION_SCOUT": "0",
        }
        registry = FrontierModelRegistry(
            environ=ai_env,
            clock=clock,
            http_post=_AcceptingAnthropicHttp(),
            resolve_dns=lambda _h: None,
        )
        quota = DailyQuotaGovernanceStore(
            root / "quota.sqlite3",
            scope_id="dual-shield-barbell",
            quota_mode=quota_mode,
            daily_quota_pct=D("0.06") if quota_mode == "PCT" else None,
            soft_quota_usd=D("500.00"),
            hard_quota_usd=D("20000.00"),
            max_loss_usd=D("10000.00"),
            max_loss_pct=D("0.04"),
        )
        trader = AutonomousAiTrader(
            router=router,
            model_registry=registry,
            valve_gate=gate,
            quota_store=quota,
            peak_equity_store=gate.peak_equity_store,
            profit_vault=vault,
            parallel_tiers=tiers,
            aggression_dial=dial,
            execution_gate=DurableModelExecutionGate(root / "model_gate.sqlite3"),
            initial_capital_usd=D("300000.00"),
            clock=clock,
        )
        stream_doc = json.loads((CONTRACTS_DIR / "initial-market-stream.json").read_text(encoding="utf-8"))
        return {
            "root": root,
            "clock": clock,
            "gate": gate,
            "emus": emus,
            "router": router,
            "dial": dial,
            "vault": vault,
            "tiers": tiers,
            "registry": registry,
            "quota": quota,
            "trader": trader,
            "stream_reader": lambda: stream_doc,
        }

    def test_cockpit_get_post_aggression_dial_contracts_and_paired_device_403(self) -> None:
        dial_schema = _load_schema("aggression-dial.schema.json")
        trader_schema = _load_schema("ai-trader.schema.json")
        tiers_schema = _load_schema("parallel-tiers.schema.json")

        with tempfile.TemporaryDirectory() as td:
            rig = self._build_300k_rig(td)
            router: DualShieldBrokerRouter = rig["router"]  # type: ignore[assignment]
            trader: AutonomousAiTrader = rig["trader"]  # type: ignore[assignment]
            tiers: ParallelTierEngine = rig["tiers"]  # type: ignore[assignment]
            vault: ProfitSweepVault = rig["vault"]  # type: ignore[assignment]
            registry: FrontierModelRegistry = rig["registry"]  # type: ignore[assignment]
            stream_reader = rig["stream_reader"]  # type: ignore[assignment]

            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                market_stream_reader=stream_reader,
                broker_router_reader=router.routing_snapshot,
                ai_model_registry=registry,
                autonomous_trader=trader,
                profit_vault=vault,
                parallel_tiers=tiers,
            )
            srv.start()
            self.addCleanup(srv.stop)

            # Unauthenticated GET & POST -> 401
            st_u1, _ = self._http_json(srv, "GET", "/api/aggression-dial")
            self.assertEqual(st_u1, 401)
            st_u2, _ = self._http_json(
                srv,
                "POST",
                "/api/aggression-dial",
                body_obj={"action": "SET_MASTER_RISK_BPS", "risk_bps": 45},
            )
            self.assertEqual(st_u2, 401)

            # Owner GET /api/aggression-dial, /api/ai-trader, /api/parallel-tiers validate against schemas
            st_ad, ad_doc = self._http_json(srv, "GET", "/api/aggression-dial", headers=srv.auth_headers())
            self.assertEqual(st_ad, 200)
            validate_contract_schema(ad_doc, dial_schema)
            _assert_no_floats_or_sensitive_keys(ad_doc)
            self.assertTrue(ad_doc["owner_controls_allowed"])
            self.assertEqual(ad_doc["access_mode"], ACCESS_MODE_OWNER_FULL_CONTROL)
            self.assertFalse(ad_doc["live_mode"])
            self.assertEqual(ad_doc["execution_mode"], "DEMO")
            self.assertTrue(ad_doc["audit_verified"])
            self.assertEqual(ad_doc["master_risk_bps"], 60)

            st_at, at_doc = self._http_json(srv, "GET", "/api/ai-trader", headers=srv.auth_headers())
            self.assertEqual(st_at, 200)
            validate_contract_schema(at_doc, trader_schema)
            _assert_no_floats_or_sensitive_keys(at_doc)
            self.assertIn("aggression_dial", at_doc)

            st_pt, pt_doc = self._http_json(srv, "GET", "/api/parallel-tiers", headers=srv.auth_headers())
            self.assertEqual(st_pt, 200)
            validate_contract_schema(pt_doc, tiers_schema)
            _assert_no_floats_or_sensitive_keys(pt_doc)
            self.assertIn("aggression_dial", pt_doc)
            for tier_row in pt_doc["tiers"]:  # type: ignore[union-attr]
                self.assertIn("aggression_dial", tier_row)

            # Mint single-use pair_code -> exchange for paired DEVICE_READ_AND_EXPLAINER session
            st_pc, pc_doc = self._http_json(srv, "POST", "/api/pair-code", headers=srv.auth_headers())
            self.assertEqual(st_pc, 200)
            st_ex, ex_doc = self._http_json(
                srv,
                "POST",
                "/api/pair-exchange",
                body_obj={"pair_code": pc_doc["pair_code"]},
            )
            self.assertEqual(st_ex, 200)
            dev_hdrs = {"Authorization": f"Bearer {ex_doc['session_token']}"}

            # Paired device can GET (read-only) with owner_controls_allowed=False
            st_dev_get, dev_ad = self._http_json(srv, "GET", "/api/aggression-dial", headers=dev_hdrs)
            self.assertEqual(st_dev_get, 200)
            validate_contract_schema(dev_ad, dial_schema)
            self.assertFalse(dev_ad["owner_controls_allowed"])
            self.assertEqual(dev_ad["access_mode"], ACCESS_MODE_DEVICE_READ_AND_EXPLAINER)

            # Paired device gets strict 403 on ALL 5 POST actions with zero audit mutation
            audit_before = int(ad_doc["audit_count"])  # type: ignore[arg-type]
            for forbidden_payload in (
                {"action": "SET_MASTER_RISK_BPS", "risk_bps": 40},
                {"action": "SET_AI_DISCRETION", "ai_discretion_enabled": False},
                {"action": "SET_AI_DISCRETION_CEILING", "ai_discretion_ceiling_bps": 75},
                {"action": "SET_TIER_RISK_BPS", "tier_id": "TIER_5_300", "risk_bps": 90},
                {"action": "APPLY_TIER_PRESET", "preset": "ALL_SAFE"},
            ):
                st_f, f_doc = self._http_json(
                    srv, "POST", "/api/aggression-dial", headers=dev_hdrs, body_obj=forbidden_payload
                )
                self.assertEqual(st_f, 403)
                self.assertEqual(f_doc["required_scope"], ACCESS_MODE_OWNER_FULL_CONTROL)
            _, after_forbidden = self._http_json(srv, "GET", "/api/aggression-dial", headers=srv.auth_headers())
            self.assertEqual(after_forbidden["audit_count"], audit_before)

            # Owner executes all 5 actions successfully
            st_m, m_doc = self._http_json(
                srv,
                "POST",
                "/api/aggression-dial",
                headers=srv.auth_headers(),
                body_obj={"action": "SET_MASTER_RISK_BPS", "risk_bps": 74},
            )
            self.assertEqual(st_m, 200)
            validate_contract_schema(m_doc, dial_schema)
            self.assertEqual(m_doc["master_risk_bps"], 74)
            self.assertEqual(m_doc["master_risk_pct"], "0.74")

            st_d1, d1_doc = self._http_json(
                srv,
                "POST",
                "/api/aggression-dial",
                headers=srv.auth_headers(),
                body_obj={"action": "SET_AI_DISCRETION", "ai_discretion_enabled": False},
            )
            self.assertEqual(st_d1, 200)
            self.assertFalse(d1_doc["ai_discretion_enabled"])
            self.assertEqual(d1_doc["ai_discretion_reason"], "MANUAL_LOCK")

            st_d2, d2_doc = self._http_json(
                srv,
                "POST",
                "/api/aggression-dial",
                headers=srv.auth_headers(),
                body_obj={"action": "TOGGLE_AI_DISCRETION"},
            )
            self.assertEqual(st_d2, 200)
            self.assertTrue(d2_doc["ai_discretion_enabled"])

            st_c, c_doc = self._http_json(
                srv,
                "POST",
                "/api/aggression-dial",
                headers=srv.auth_headers(),
                body_obj={"action": "SET_AI_DISCRETION_CEILING", "ai_discretion_ceiling_bps": 88},
            )
            self.assertEqual(st_c, 200)
            self.assertEqual(c_doc["ai_discretion_ceiling_bps"], 88)

            st_t, t_doc = self._http_json(
                srv,
                "POST",
                "/api/aggression-dial",
                headers=srv.auth_headers(),
                body_obj={"action": "SET_TIER_RISK_BPS", "tier_id": "TIER_3_3000", "risk_bps": 67},
            )
            self.assertEqual(st_t, 200)
            self.assertEqual(t_doc["tiers_by_id"]["TIER_3_3000"]["risk_bps"], 67)  # type: ignore[index]

            # Presets: STAGGER_SAFE_TO_EXTREME, ALL_BALANCED, SYNC_ALL_TO_MASTER
            st_p1, p1_doc = self._http_json(
                srv,
                "POST",
                "/api/aggression-dial",
                headers=srv.auth_headers(),
                body_obj={"action": "APPLY_TIER_PRESET", "preset": PRESET_STAGGER_SAFE_TO_EXTREME},
            )
            self.assertEqual(st_p1, 200)
            self.assertEqual(p1_doc["tiers_by_id"]["TIER_1_CURRENT"]["risk_bps"], 25)  # type: ignore[index]
            self.assertEqual(p1_doc["tiers_by_id"]["TIER_5_300"]["risk_bps"], 100)  # type: ignore[index]

            st_p2, p2_doc = self._http_json(
                srv,
                "POST",
                "/api/aggression-dial",
                headers=srv.auth_headers(),
                body_obj={"action": "APPLY_TIER_PRESET", "preset": PRESET_ALL_BALANCED},
            )
            self.assertEqual(st_p2, 200)
            for tr in p2_doc["tiers"]:  # type: ignore[union-attr]
                self.assertEqual(tr["risk_bps"], 60)

            st_p3, p3_doc = self._http_json(
                srv,
                "POST",
                "/api/aggression-dial",
                headers=srv.auth_headers(),
                body_obj={"action": "APPLY_TIER_PRESET", "preset": PRESET_SYNC_ALL_TO_MASTER},
            )
            self.assertEqual(st_p3, 200)
            for tr in p3_doc["tiers"]:  # type: ignore[union-attr]
                self.assertEqual(tr["risk_bps"], 74)
            self.assertTrue(p3_doc["audit_verified"])

            # Verify parallel-tiers endpoint reflects synced 74 bps immediately
            _, pt_synced = self._http_json(srv, "GET", "/api/parallel-tiers", headers=srv.auth_headers())
            validate_contract_schema(pt_synced, tiers_schema)
            for tr in pt_synced["tiers"]:  # type: ignore[union-attr]
                self.assertEqual(tr["aggression_dial"]["risk_bps"], 74)

            # Metrics route tracking
            st_met, met_doc = self._http_json(srv, "GET", "/api/metrics", headers=srv.auth_headers())
            self.assertEqual(st_met, 200)
            self.assertTrue(met_doc["components"]["aggression_dial"])  # type: ignore[index]
            self.assertGreaterEqual(met_doc["route_counts"].get("/api/aggression-dial", 0), 8)  # type: ignore[union-attr]

    def test_live_mode_high_risk_409_confirmation_gate_and_anti_spoof(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            dial = AggressionDialStore(
                Path(td) / "live_dial.sqlite3",
                initial_ai_discretion_ceiling_bps=79,
                now_fn=_StepClock(),
            )
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                broker_router_reader=lambda: {"execution_mode": "LIVE"},
                aggression_dial=dial,
            )
            srv.start()
            self.addCleanup(srv.stop)

            st_get, doc = self._http_json(srv, "GET", "/api/aggression-dial", headers=srv.auth_headers())
            self.assertEqual(st_get, 200)
            self.assertTrue(doc["live_mode"])
            self.assertEqual(doc["execution_mode"], "LIVE")

            # 79 bps (< 80) succeeds without extra confirmation
            st_79, doc_79 = self._http_json(
                srv,
                "POST",
                "/api/aggression-dial",
                headers=srv.auth_headers(),
                body_obj={"action": "SET_MASTER_RISK_BPS", "risk_bps": 79},
            )
            self.assertEqual(st_79, 200)
            self.assertEqual(doc_79["master_risk_bps"], 79)

            # >= 80 bps without high_risk_confirmed=True MUST return 409 Conflict (even if spoofing live_mode=False)
            audit_before = int(doc_79["audit_count"])  # type: ignore[arg-type]
            for high_payload in (
                {"action": "SET_MASTER_RISK_BPS", "risk_bps": 80, "high_risk_confirmed": False},
                {"action": "SET_MASTER_RISK_BPS", "risk_bps": 100, "live_mode": False},
                {"action": "SET_TIER_RISK_BPS", "tier_id": "TIER_5_300", "risk_bps": 85},
                {"action": "SET_AI_DISCRETION_CEILING", "ai_discretion_ceiling_bps": 95},
                {"action": "APPLY_TIER_PRESET", "preset": "STAGGER_SAFE_TO_EXTREME"},
            ):
                st_409, err_409 = self._http_json(
                    srv, "POST", "/api/aggression-dial", headers=srv.auth_headers(), body_obj=high_payload
                )
                self.assertEqual(st_409, 409)
                self.assertEqual(err_409["code"], "HIGH_RISK_CONFIRMATION_REQUIRED")
                self.assertEqual(err_409["high_risk_min_bps"], 80)
            self.assertEqual(dial.snapshot()["audit_count"], audit_before)

            # Unbound high_risk_confirmed=True without target-bound confirmation is also rejected (Finding [17])
            st_unb1, unb1 = self._http_json(
                srv,
                "POST",
                "/api/aggression-dial",
                headers=srv.auth_headers(),
                body_obj={"action": "SET_MASTER_RISK_BPS", "risk_bps": 100, "high_risk_confirmed": True},
            )
            self.assertEqual(st_unb1, 409)

            # With exact target-bound confirmation, 100 bps & STAGGER_SAFE_TO_EXTREME succeed in LIVE mode
            st_ok1, ok1 = self._http_json(
                srv,
                "POST",
                "/api/aggression-dial",
                headers=srv.auth_headers(),
                body_obj={
                    "action": "SET_MASTER_RISK_BPS",
                    "risk_bps": 100,
                    "high_risk_confirmed": True,
                    "high_risk_confirmation": unb1["required_confirmation"],
                },
            )
            self.assertEqual(st_ok1, 200)
            self.assertEqual(ok1["master_risk_bps"], 100)

            st_unb2, unb2 = self._http_json(
                srv,
                "POST",
                "/api/aggression-dial",
                headers=srv.auth_headers(),
                body_obj={
                    "action": "APPLY_TIER_PRESET",
                    "preset": "STAGGER_SAFE_TO_EXTREME",
                    "high_risk_confirmed": True,
                },
            )
            self.assertEqual(st_unb2, 409)

            st_ok2, ok2 = self._http_json(
                srv,
                "POST",
                "/api/aggression-dial",
                headers=srv.auth_headers(),
                body_obj={
                    "action": "APPLY_TIER_PRESET",
                    "preset": "STAGGER_SAFE_TO_EXTREME",
                    "high_risk_confirmed": True,
                    "confirmation_phrase": unb2["required_confirmation_phrase"],
                },
            )
            self.assertEqual(st_ok2, 200)
            self.assertEqual(ok2["tiers_by_id"]["TIER_5_300"]["risk_bps"], 100)  # type: ignore[index]
            self.assertTrue(ok2["audit_verified"])

    def test_zero_write_snapshots_and_sse_aggression_dial_events(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rig = self._build_300k_rig(td)
            root: Path = rig["root"]  # type: ignore[assignment]
            router: DualShieldBrokerRouter = rig["router"]  # type: ignore[assignment]
            trader: AutonomousAiTrader = rig["trader"]  # type: ignore[assignment]
            tiers: ParallelTierEngine = rig["tiers"]  # type: ignore[assignment]
            vault: ProfitSweepVault = rig["vault"]  # type: ignore[assignment]
            registry: FrontierModelRegistry = rig["registry"]  # type: ignore[assignment]
            stream_reader = rig["stream_reader"]  # type: ignore[assignment]

            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                market_stream_reader=stream_reader,
                broker_router_reader=router.routing_snapshot,
                ai_model_registry=registry,
                autonomous_trader=trader,
                profit_vault=vault,
                parallel_tiers=tiers,
            )
            srv.start()
            self.addCleanup(srv.stop)

            db_files = [
                root / "aggression_dial.sqlite3",
                root / "tiers.sqlite3",
                root / "tiers_vault.sqlite3",
                root / "vault.sqlite3",
            ]
            before_dv: dict[str, int] = {}
            observers: list[sqlite3.Connection] = []
            try:
                for dbf in db_files:
                    c = sqlite3.connect(str(dbf))
                    observers.append(c)
                    before_dv[dbf.name] = int(c.execute("PRAGMA data_version").fetchone()[0])

                for _ in range(3):
                    s1, _ = self._http_json(srv, "GET", "/api/aggression-dial", headers=srv.auth_headers())
                    s2, _ = self._http_json(srv, "GET", "/api/ai-trader", headers=srv.auth_headers())
                    s3, _ = self._http_json(srv, "GET", "/api/parallel-tiers", headers=srv.auth_headers())
                    self.assertEqual((s1, s2, s3), (200, 200, 200))
                    trader.status_snapshot()
                    tiers.snapshot()

                for idx, dbf in enumerate(db_files):
                    after_dv = int(observers[idx].execute("PRAGMA data_version").fetchone()[0])
                    self.assertEqual(before_dv[dbf.name], after_dv, f"Unexpected SQLite write on {dbf.name}")
            finally:
                for c in observers:
                    c.close()

            # SSE /api/market-events emits event: aggression_dial on connect and on dial mutation
            sock = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
            try:
                req = (
                    f"GET /api/market-events HTTP/1.1\r\n"
                    f"Host: {srv.expected_host_header}\r\n"
                    f"Authorization: Bearer {srv.auth_token}\r\n\r\n"
                ).encode("ascii")
                sock.sendall(req)
                buf = b""
                deadline = time.monotonic() + 3.0
                while b"event: aggression_dial\n" not in buf:
                    if time.monotonic() > deadline:
                        self.fail(f"Timed out waiting for initial SSE aggression_dial; got {buf[:300]!r}")
                    buf += sock.recv(8192)
                self.assertIn(b'"master_risk_bps": 60', buf)

                buf = b""
                st_upd, _ = self._http_json(
                    srv,
                    "POST",
                    "/api/aggression-dial",
                    headers=srv.auth_headers(),
                    body_obj={"action": "SET_MASTER_RISK_BPS", "risk_bps": 42},
                )
                self.assertEqual(st_upd, 200)
                deadline2 = time.monotonic() + 3.0
                while b'"master_risk_bps": 42' not in buf:
                    if time.monotonic() > deadline2:
                        self.fail(f"Timed out waiting for updated SSE aggression_dial; got {buf[:300]!r}")
                    buf += sock.recv(8192)
            finally:
                sock.close()
                srv.stop()

    def test_parallel_tiers_5_tier_sizing_max_open_trades_prob_and_goals(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clock = _StepClock()
            base_gate = load_default_forex_valve_gate(peak_equity_store=PeakEquityStore(root / "pk.sqlite3"))

            # 1. Per-tier risk_pct (25 bps vs 100 bps) & max_open_trades (1 vs 2+)
            dial = AggressionDialStore(root / "dial.sqlite3", now_fn=clock)
            dial.apply_tier_preset(PRESET_STAGGER_SAFE_TO_EXTREME, actor="wakil")
            dial.set_all_tiers_ai_discretion(False, actor="wakil")
            tiers = ParallelTierEngine(root / "tiers.sqlite3", valve_gate=base_gate, aggression_dial=dial, clock=clock)

            # Tight 25-pip stop on EURUSD (1.10010 -> 1.09760 = 0.00250 => $2.50 risk on 0.01 lot)
            # TIER_5_300 at 100 bps has $3.00 budget -> admits 0.01 lot (1,000 units)!
            # TIER_1_CURRENT at 25 bps has $750.00 budget -> 300,000 units (3.00 lots)!
            snap1 = tiers.process_tick(
                quotes=BASE_QUOTES,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09760",
                    "take_profit_price": "1.10600",
                    "regime": "STRONG_TREND",
                },
                now=clock(),
            )
            by_id1 = {t["tier_id"]: t for t in snap1["tiers"]}
            self.assertEqual(by_id1["TIER_1_CURRENT"]["open_positions"], 1)
            self.assertEqual(by_id1["TIER_5_300"]["open_positions"], 1)

            with closing(sqlite3.connect(str(root / "tiers.sqlite3"))) as conn:
                u_300k_25bps = Decimal(
                    conn.execute("SELECT units FROM tier_positions WHERE tier_id = 'TIER_1_CURRENT'").fetchone()[0]
                )
                u_300_100bps = Decimal(
                    conn.execute("SELECT units FROM tier_positions WHERE tier_id = 'TIER_5_300'").fetchone()[0]
                )
            self.assertEqual(u_300k_25bps, D("300000"))
            self.assertEqual(u_300_100bps, D("1000"))

            # 2nd signal on GBPUSD: TIER_1_CURRENT (25 bps => max_open_trades=1) MUST skip with MAX_OPEN_TRADES_REACHED!
            # TIER_4_6000 (45 bps => max_open_trades=2) opens its 2nd trade!
            snap2 = tiers.process_tick(
                quotes=BASE_QUOTES,
                signal={
                    "symbol": "GBPUSD",
                    "side": "BUY",
                    "stop_price": "1.26500",
                    "take_profit_price": "1.28000",
                    "regime": "STRONG_TREND",
                },
                now=clock(),
            )
            by_id2 = {t["tier_id"]: t for t in snap2["tiers"]}
            self.assertEqual(by_id2["TIER_1_CURRENT"]["open_positions"], 1)
            self.assertIn("MAX_OPEN_TRADES_REACHED", str(by_id2["TIER_1_CURRENT"]["last_skip_reason"]))
            self.assertEqual(by_id2["TIER_4_6000"]["open_positions"], 2)

            # 2. Per-tier min_signal_prob (0.55..0.78) with forced Valve score = 0.62
            gate_62 = _FixedScoreValveGate(base_gate, forced_score=0.62)
            dial2 = AggressionDialStore(root / "dial2.sqlite3", now_fn=clock)
            dial2.apply_tier_preset(PRESET_STAGGER_SAFE_TO_EXTREME, actor="wakil")
            dial2.set_all_tiers_ai_discretion(False, actor="wakil")
            tiers2 = ParallelTierEngine(root / "tiers2.sqlite3", valve_gate=gate_62, aggression_dial=dial2, clock=clock)
            snap_prob = tiers2.process_tick(
                quotes=BASE_QUOTES,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09760",
                    "take_profit_price": "1.10600",
                    "regime": "STRONG_TREND",
                },
                now=clock(),
            )
            by_prob = {t["tier_id"]: t for t in snap_prob["tiers"]}
            # 25 bps (0.76), 45 bps (0.71), 65 bps (0.65) > 0.62 => skipped by DIAL_MIN_SIGNAL_PROB
            for blocked_tid in ("TIER_1_CURRENT", "TIER_4_6000", "TIER_3_3000"):
                self.assertEqual(by_prob[blocked_tid]["open_positions"], 0)
                self.assertIn("DIAL_MIN_SIGNAL_PROB", str(by_prob[blocked_tid]["last_skip_reason"]))
            # 85 bps (0.59) and 100 bps (0.55) <= 0.62 => admitted!
            self.assertEqual(by_prob["TIER_2_1000"]["open_positions"], 1)
            self.assertEqual(by_prob["TIER_5_300"]["open_positions"], 1)

            # Sub-0.55 Valve score (0.51) is unconditionally refused by ForexMetaValveGate even at 100 bps
            gate_62.forced_score = 0.51
            snap_sub55 = tiers2.process_tick(
                quotes=BASE_QUOTES,
                signal={
                    "symbol": "GBPUSD",
                    "side": "BUY",
                    "stop_price": "1.26760",
                    "take_profit_price": "1.27600",
                    "regime": "STRONG_TREND",
                },
                now=clock(),
            )
            by_sub55 = {t["tier_id"]: t for t in snap_sub55["tiers"]}
            self.assertIn("VALVE_REFUSED", str(by_sub55["TIER_5_300"]["last_skip_reason"]))

            # 3. Proportional session_goal_usd ($15.00 at 100 bps on $300) & daily_loss_brake_usd ($0.75 at 20 bps on $300)
            dial3 = AggressionDialStore(root / "dial3.sqlite3", now_fn=clock)
            dial3.set_tier_risk_bps("TIER_5_300", 100, actor="wakil")
            tiers3 = ParallelTierEngine(root / "tiers3.sqlite3", valve_gate=base_gate, aggression_dial=dial3, clock=clock)
            ts_now = clock()
            tiers3._quotas["TIER_5_300"].observe_day_start(D("300.00"), now=ts_now)
            # +$8.00 is above legacy 2.5% ($7.50) but below 100-bps $15.00 goal -> MUST still admit!
            tiers3._quotas["TIER_5_300"].record_realized_trade(
                D("8.00"), symbol="EURUSD", ticket="t1", starting_equity=D("300.00"), now=ts_now
            )
            s_open = tiers3.process_tick(
                quotes=BASE_QUOTES,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09760",
                    "take_profit_price": "1.10600",
                    "regime": "STRONG_TREND",
                },
                now=clock(),
            )
            self.assertEqual({t["tier_id"]: t for t in s_open["tiers"]}["TIER_5_300"]["open_positions"], 1)

            # +$7.50 more => +$15.50 >= $15.00 session_goal_usd -> cold OPEN blocked by SESSION_GOAL_REACHED
            tiers3._quotas["TIER_5_300"].record_realized_trade(
                D("7.50"), symbol="EURUSD", ticket="t2", starting_equity=D("308.00"), now=clock()
            )
            s_goal = tiers3.process_tick(
                quotes=BASE_QUOTES,
                signal={
                    "symbol": "GBPUSD",
                    "side": "BUY",
                    "stop_price": "1.26760",
                    "take_profit_price": "1.27600",
                    "regime": "TREND_IGNITION",
                },
                now=clock(),
            )
            self.assertIn(
                "SESSION_GOAL_REACHED",
                str({t["tier_id"]: t for t in s_goal["tiers"]}["TIER_5_300"]["last_skip_reason"]),
            )

            # Switch TIER_2_1000 to 20 bps Safe (daily_loss_brake_usd = $2.50) and record -$2.60 loss -> DAILY_LOSS_BRAKE
            dial3.set_tier_risk_bps("TIER_2_1000", 20, actor="wakil")
            t_loss = clock()
            tiers3._quotas["TIER_2_1000"].observe_day_start(D("1000.00"), now=t_loss)
            tiers3._quotas["TIER_2_1000"].record_realized_trade(
                D("-2.60"), symbol="EURUSD", ticket="tl1", starting_equity=D("1000.00"), now=t_loss
            )
            s_brake = tiers3.process_tick(
                quotes=BASE_QUOTES,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09800",
                    "take_profit_price": "1.10500",
                    "regime": "STRONG_TREND",
                },
                now=clock(),
            )
            self.assertIn(
                "DAILY_LOSS_BRAKE",
                str({t["tier_id"]: t for t in s_brake["tiers"]}["TIER_2_1000"]["last_skip_reason"]),
            )

    def test_master_trader_ai_discretion_bidirectional_manual_lock_and_cli_check(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rig = self._build_300k_rig(td, forced_valve_score=0.76)
            trader: AutonomousAiTrader = rig["trader"]  # type: ignore[assignment]
            dial: AggressionDialStore = rig["dial"]  # type: ignore[assignment]
            clock: _StepClock = rig["clock"]  # type: ignore[assignment]

            # 1. Initial Master=60 bps, AI Discretion=True, default last_regime=TREND_IGNITION => shifts UP to 85 bps!
            snap0 = trader.status_snapshot(now=clock())
            self.assertEqual(snap0["aggression_dial"]["master_risk_bps"], 60)
            self.assertEqual(snap0["aggression_dial"]["effective_risk_bps"], 85)
            self.assertEqual(snap0["aggression_dial"]["ai_discretion_direction"], "UP")

            # 2. Flat CHOP_RANGE ticks on NAS100 across 4 cycles => last_regime becomes CHOP_RANGE => shifts DOWN to 40 bps!
            chop_quotes = dict(BASE_QUOTES)
            for _ in range(4):
                rep_chop = trader.run_cycle(None, mt5_quotes=chop_quotes, fast_tick=True, now=clock())
            self.assertEqual(rep_chop["action"], "WAIT")
            snap_chop = trader.status_snapshot(now=clock())
            self.assertEqual(snap_chop["last_regime"], "CHOP_RANGE")
            self.assertEqual(snap_chop["aggression_dial"]["effective_risk_bps"], 40)
            self.assertEqual(snap_chop["aggression_dial"]["ai_discretion_direction"], "DOWN")
            self.assertEqual(snap_chop["aggression_dial"]["ai_discretion_reason"], "CHOP_RANGE")

            # 3. STRONG_TREND upward ignition on NAS100 with valve_score=0.76 >= 0.72:
            # First clamp ceiling=88 => AI Discretion boosts 60 -> 88 bps (respecting ceiling <= 100 bps)
            dial.set_ai_discretion(True, ceiling_bps=88, actor="wakil")
            trader._tick_history["NAS100"].clear()
            for step in range(1, 41):
                b = D("20260.00") + D(step) * D("6.00")
                trader._tick_history["NAS100"].append((b, b + D("2.00")))
            burst_quotes = dict(BASE_QUOTES)
            rep_open = trader.run_cycle(None, mt5_quotes=burst_quotes, fast_tick=True, now=clock())
            self.assertEqual(rep_open["action"], "OPEN_BUY")
            snap_st88 = trader.status_snapshot(now=clock())
            self.assertEqual(snap_st88["aggression_dial"]["effective_risk_bps"], 88)

            # Raise ceiling to 100 => STRONG_TREND + valve_score 0.76 shifts UP to 100 bps (1.00% Extreme High Risk)
            dial.set_ai_discretion(True, ceiling_bps=100, actor="wakil")
            snap_st100 = trader.status_snapshot(now=clock())
            self.assertEqual(snap_st100["aggression_dial"]["effective_risk_bps"], 100)
            self.assertEqual(snap_st100["aggression_dial"]["effective_risk_pct"], "1.00")

            # 4. Consecutive losses & drawdown downshifts: 1 loss -> 40 bps, 2 losses -> 30 bps, 8.5% DD -> 20 bps
            trader.record_closed_pnl(D("-200.00"), symbol="NAS100", ticket="loss-1", now=clock())
            self.assertEqual(trader.status_snapshot(now=clock())["aggression_dial"]["effective_risk_bps"], 40)
            trader.record_closed_pnl(D("-200.00"), symbol="NAS100", ticket="loss-2", now=clock())
            self.assertEqual(trader.status_snapshot(now=clock())["aggression_dial"]["effective_risk_bps"], 30)

            trader._peak_store.observe_equity(
                trader._router._drawdown_scope_id,
                current_equity=D("330000.00"),
                opening_balance=D("330000.00"),
                now=clock(),
            )
            self.assertEqual(trader.status_snapshot(now=clock())["aggression_dial"]["effective_risk_bps"], 20)

            # 5. Manual Lock (ai_discretion_enabled=False) at 37 bps pins effective_risk_bps=37 regardless of DD/losses/regime
            dial.set_ai_discretion(False, actor="wakil")
            dial.set_master_risk_bps(37, actor="wakil")
            snap_lock = trader.status_snapshot(now=clock())
            self.assertEqual(snap_lock["aggression_dial"]["effective_risk_bps"], 37)
            self.assertEqual(snap_lock["aggression_dial"]["effective_risk_pct"], "0.37")
            self.assertEqual(snap_lock["aggression_dial"]["ai_discretion_reason"], "MANUAL_LOCK")

        # 6. Master max_open_trades (Safe 20 bps => 1 open trade max) & min_signal_prob (0.78 > 0.64)
        with tempfile.TemporaryDirectory() as td2:
            rig2 = self._build_300k_rig(td2, forced_valve_score=0.64)
            trader2: AutonomousAiTrader = rig2["trader"]  # type: ignore[assignment]
            dial2: AggressionDialStore = rig2["dial"]  # type: ignore[assignment]
            tiers2: ParallelTierEngine = rig2["tiers"]  # type: ignore[assignment]
            clock2: _StepClock = rig2["clock"]  # type: ignore[assignment]

            # Master locked at 20 bps Safe (min_signal_prob=0.78), TIER_5_300 at 100 bps (min_signal_prob=0.55)
            dial2.set_ai_discretion(False, actor="wakil")
            dial2.set_master_risk_bps(20, actor="wakil")
            dial2.set_tier_risk_bps("TIER_5_300", 100, actor="wakil")

            for step in range(1, 12):
                b = D("20428.00") + D(step) * D("6.00")
                trader2._tick_history["NAS100"].append((b, b + D("2.00")))
            q_burst = dict(BASE_QUOTES)
            # Valve score 0.64 < 0.78 => Master holds WAIT with DIAL_MIN_SIGNAL_PROB, while TIER_5_300 evaluates signal!
            rep_prob = trader2.run_cycle(None, mt5_quotes=q_burst, fast_tick=True, now=clock2())
            self.assertEqual(rep_prob["action"], "WAIT")
            self.assertIn("DIAL_MIN_SIGNAL_PROB", str(rep_prob["reason"]))
            self.assertEqual(len(trader2._open_position_meta), 0)

            # Raise forced Valve score to 0.82 >= 0.78 => Master opens 1st trade; 2nd cycle on US30 hits DIAL_MAX_OPEN_TRADES_REACHED (1>=1)
            gate2: _FixedScoreValveGate = rig2["gate"]  # type: ignore[assignment]
            gate2.forced_score = 0.82
            rep_first = trader2.run_cycle(None, mt5_quotes=q_burst, fast_tick=True, now=clock2())
            self.assertEqual(rep_first["action"], "OPEN_BUY")
            self.assertEqual(len(trader2._open_position_meta), 1)

            for step in range(1, 12):
                b30 = D("43656.00") + D(step) * D("12.00")
                trader2._tick_history["US30"].append((b30, b30 + D("4.00")))
            q_us30 = dict(BASE_QUOTES)
            rep_cap = trader2.run_cycle(None, mt5_quotes=q_us30, fast_tick=True, now=clock2())
            self.assertEqual(rep_cap["action"], "WAIT")
            self.assertIn("DIAL_MAX_OPEN_TRADES_REACHED", str(rep_cap["reason"]))

            # Master daily_loss_brake_usd ($750 at 20 bps on $300k): -$800 realized loss blocks new risk
            trader2.record_closed_pnl(D("-800.00"), symbol="EURUSD", ticket="m-loss-brake", now=clock2())
            rep_brake = trader2.run_cycle(None, mt5_quotes=q_us30, fast_tick=True, now=clock2())
            self.assertEqual(rep_brake["action"], "WAIT")
            self.assertIn("DIAL_DAILY_LOSS_BRAKE", str(rep_brake["reason"]))
            _ = tiers2.snapshot()

            # 7. run_cockpit_cli --print-check-only creates aggression_dial.sqlite3 and reports master bps
            cli_state = Path(td2) / "cli_state"
            buf_out = io.StringIO()
            with redirect_stdout(buf_out):
                rc = run_cockpit_cli(
                    ["--print-check-only", "--state-dir", str(cli_state)],
                    environ={},
                    repo_root=REPO_ROOT,
                )
            self.assertEqual(rc, 0)
            cli_doc = json.loads(buf_out.getvalue())
            self.assertEqual(cli_doc["aggression_dial_master_bps"], 60)
            self.assertTrue((cli_state / "aggression_dial.sqlite3").is_file())


    def test_five_tier_ai_discretion_live_engine_per_tier_toggles_and_legacy_migration(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clock = _StepClock()
            base_gate = load_default_forex_valve_gate(peak_equity_store=PeakEquityStore(root / "pk.sqlite3"))

            # 1. Legacy SQLite migration: existing dial_tiers without ai_discretion_enabled upgrades cleanly to ON (1)
            legacy_db = root / "legacy_dial.sqlite3"
            with closing(sqlite3.connect(str(legacy_db))) as conn:
                conn.execute(
                    "CREATE TABLE dial_state (scope_id TEXT PRIMARY KEY, master_risk_bps INTEGER NOT NULL, "
                    "auto_shift_enabled INTEGER NOT NULL, ai_discretion_enabled INTEGER NOT NULL DEFAULT 1, "
                    "ai_discretion_ceiling_bps INTEGER NOT NULL DEFAULT 100, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL)"
                )
                conn.execute(
                    "CREATE TABLE dial_tiers (scope_id TEXT NOT NULL, tier_id TEXT NOT NULL, risk_bps INTEGER NOT NULL, "
                    "capital_usd TEXT NOT NULL, label TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL, "
                    "PRIMARY KEY (scope_id, tier_id))"
                )
                conn.execute(
                    "INSERT INTO dial_state VALUES ('default', 60, 1, 1, 100, '2026-11-20T00:00:00Z', 'legacy')"
                )
                conn.execute(
                    "INSERT INTO dial_tiers VALUES ('default', 'TIER_4_6000', 93, '6000.00', 'Tier $6,000 Accelerator', '2026-11-20T00:00:00Z', 'legacy')"
                )
                conn.commit()
            migrated = AggressionDialStore(legacy_db, now_fn=clock)
            mig_snap = migrated.snapshot(regime="STRONG_TREND")
            self.assertTrue(mig_snap["tiers_by_id"]["TIER_4_6000"]["ai_discretion_enabled"])
            self.assertEqual(mig_snap["tiers_by_id"]["TIER_4_6000"]["risk_bps"], 93)
            self.assertEqual(mig_snap["tiers_by_id"]["TIER_4_6000"]["effective_risk_bps"], 95)

            # 2. Live 5-tier ParallelTierEngine: AI Discretion ON boosts TIER_1_CURRENT (base 25 bps -> 95 bps = 1,140,000 units)
            # while individually locking TIER_4_6000 (base 45 bps -> stays 45 bps = $27.00 / 0.0025 = 10,000 units ROUND_FLOOR)!
            dial = AggressionDialStore(root / "dial.sqlite3", now_fn=clock)
            dial.apply_tier_preset(PRESET_STAGGER_SAFE_TO_EXTREME, actor="wakil")
            dial.set_tier_ai_discretion("TIER_4_6000", False, actor="wakil")
            tiers = ParallelTierEngine(root / "tiers.sqlite3", valve_gate=base_gate, aggression_dial=dial, clock=clock)

            snap_st = tiers.process_tick(
                quotes=BASE_QUOTES,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09760",
                    "take_profit_price": "1.10600",
                    "regime": "STRONG_TREND",
                },
                now=clock(),
            )
            by_id = {t["tier_id"]: t for t in snap_st["tiers"]}
            self.assertTrue(by_id["TIER_1_CURRENT"]["aggression_dial"]["ai_discretion_enabled"])
            self.assertEqual(by_id["TIER_1_CURRENT"]["aggression_dial"]["effective_risk_bps"], 95)
            self.assertTrue(by_id["TIER_1_CURRENT"]["aggression_dial"]["ai_discretion_shifted"])
            self.assertFalse(by_id["TIER_4_6000"]["aggression_dial"]["ai_discretion_enabled"])
            self.assertEqual(by_id["TIER_4_6000"]["aggression_dial"]["effective_risk_bps"], 45)
            self.assertFalse(by_id["TIER_4_6000"]["aggression_dial"]["ai_discretion_shifted"])

            with closing(sqlite3.connect(str(root / "tiers.sqlite3"))) as conn:
                u_t1 = Decimal(conn.execute("SELECT units FROM tier_positions WHERE tier_id = 'TIER_1_CURRENT'").fetchone()[0])
                u_t4 = Decimal(conn.execute("SELECT units FROM tier_positions WHERE tier_id = 'TIER_4_6000'").fetchone()[0])
            self.assertEqual(u_t1, D("1140000"))
            self.assertEqual(u_t4, D("10000"))

            # 3. Cockpit API SET_TIER_AI_DISCRETION & SET_ALL_TIERS_AI_DISCRETION + contract validation
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                broker_router_reader=lambda: {"execution_mode": "DEMO", "live_trading_armed": False},
                aggression_dial=dial,
                parallel_tiers=tiers,
            )
            srv.start()
            try:
                st_live_blk, _ = self._http_json(
                    srv,
                    "POST",
                    "/api/aggression-dial",
                    headers=srv.auth_headers(),
                    body_obj={
                        "action": "SET_TIER_AI_DISCRETION",
                        "tier_id": "TIER_4_6000",
                        "ai_discretion_enabled": True,
                        "live_mode": True,
                    },
                )
                self.assertEqual(st_live_blk, 409)

                st_on, doc_on = self._http_json(
                    srv,
                    "POST",
                    "/api/aggression-dial",
                    headers=srv.auth_headers(),
                    body_obj={"action": "SET_TIER_AI_DISCRETION", "tier_id": "TIER_4_6000", "ai_discretion_enabled": True},
                )
                self.assertEqual(st_on, 200)
                self.assertTrue(doc_on["tiers_by_id"]["TIER_4_6000"]["ai_discretion_enabled"])
                ad_schema = _load_schema("aggression-dial.schema.json")
                validate_contract_schema(doc_on, ad_schema, ad_schema, "$")

                st_all, doc_all = self._http_json(
                    srv,
                    "POST",
                    "/api/aggression-dial",
                    headers=srv.auth_headers(),
                    body_obj={"action": "SET_ALL_TIERS_AI_DISCRETION", "ai_discretion_enabled": False},
                )
                self.assertEqual(st_all, 200)
                self.assertTrue(all(not t["ai_discretion_enabled"] for t in doc_all["tiers"]))
                validate_contract_schema(doc_all, ad_schema, ad_schema, "$")
                self.assertTrue(dial.verify_audit_chain())
            finally:
                srv.stop()

    def test_pr26_backend_source_hygiene_zero_assert_zero_crlf(self) -> None:
        owned_files = [
            REPO_ROOT / "src" / "cas_forex_revamp" / "valve" / "aggression_dial.py",
            REPO_ROOT / "src" / "cas_forex_revamp" / "composition" / "parallel_tiers.py",
            REPO_ROOT / "src" / "cas_forex_revamp" / "composition" / "autonomous_trader.py",
            REPO_ROOT / "src" / "cas_forex_revamp" / "composition" / "live_cockpit_server.py",
            Path(__file__).resolve(),
        ]
        cr_byte = bytes([13])
        bom_bytes = bytes([0xEF, 0xBB, 0xBF])
        for fp in owned_files:
            raw = fp.read_bytes()
            self.assertFalse(raw.startswith(bom_bytes), f"UTF-8 BOM in {fp.name}")
            self.assertNotIn(cr_byte, raw, f"CR byte in {fp.name}")
            tree = ast.parse(raw.decode("utf-8"), filename=str(fp))
            assert_nodes = [n for n in ast.walk(tree) if isinstance(n, ast.Assert)]
            self.assertEqual(assert_nodes, [], f"Bandit B101 assert in {fp.name}")


if __name__ == "__main__":
    unittest.main()
