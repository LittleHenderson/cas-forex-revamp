"""End-to-end integration tests for PR #28: 100% Compounding Mode, House-Money Alert & Live Phase 8 Bridge."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest

from cas_forex_revamp.composition.autonomous_trader import (
    AutonomousAiTrader,
    RISK_GEAR_AGGRESSIVE,
)
from cas_forex_revamp.composition.live_cockpit_server import (
    SESSION_SCOPE_DEVICE_READ_EXPLAINER,
    SESSION_SCOPE_OWNER_FULL,
    LoopbackCockpitServer,
)
from cas_forex_revamp.contracts import (
    ActionIntent,
    ActionKind,
    ActionOption,
    ContractError,
    DecisionFact,
    DecisionOrigin,
    DecisionProvenance,
    DecisionRequest,
    DecisionResult,
    DecisionSelection,
    EvidenceKind,
    EvidenceReference,
    RunScope,
    Side,
    StateReference,
    canonical_bytes,
    content_digest,
)
from cas_forex_revamp.execution.smart_execution import AccountMarginState, QuoteSnapshot
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.risk.news_shock_shield import EconomicEvent, NewsImpact, NewsShockShield
from cas_forex_revamp.treasury.compounding_controller import (
    CompoundingAndMilestoneController,
    CompoundingMode,
    STATUS_BUILDING_TOWARD_PRINCIPAL,
    STATUS_COMPOUNDING_TO_DOUBLE,
    STATUS_HOUSE_MONEY_READY,
    STATUS_PLAYING_ON_HOUSE_MONEY,
)
from cas_forex_revamp.treasury.profit_sweep import ProfitSweepVault
from cas_forex_revamp.valve.aggression_dial import AggressionDialStore
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    PeakEquityStore,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.dual_shield_router import (
    BarbellCapitalPolicy,
    DualShieldBrokerRouter,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    Mt5Credentials,
    Mt5PaperBrokerVenue,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    OrderIntent,
)
from tests.phase6.test_cockpit_api_contracts import (
    SUPPORTED_SCHEMA_KEYWORDS,
    validate_contract_schema,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOUNDING_SCHEMA_PATH = REPO_ROOT / "docs" / "contracts" / "compounding.schema.json"
T_BASE = datetime(2026, 11, 20, 13, 20, 0, tzinfo=timezone.utc)


def _sqlite_data_version(db_path: Path) -> int:
    if not db_path.exists():
        return -1
    uri = f"{db_path.resolve().as_uri()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    try:
        row = conn.execute("PRAGMA data_version").fetchone()
        return int(row[0]) if row is not None else -1
    finally:
        conn.close()


def _check_all_objects_forbid_additional_properties(schema_node: object, path: str = "$") -> list[str]:
    issues: list[str] = []
    if isinstance(schema_node, dict):
        for kw in schema_node:
            if kw not in SUPPORTED_SCHEMA_KEYWORDS:
                issues.append(f"{path}: unsupported keyword {kw!r}")
        if schema_node.get("type") == "object" and schema_node.get("additionalProperties") is not False:
            issues.append(f"{path}: object missing additionalProperties: false")
        for k, v in schema_node.items():
            if k in ("properties", "$defs") and isinstance(v, dict):
                for sub_k, sub_v in v.items():
                    issues.extend(_check_all_objects_forbid_additional_properties(sub_v, f"{path}.{k}.{sub_k}"))
            elif k == "items" and isinstance(v, dict):
                issues.extend(_check_all_objects_forbid_additional_properties(v, f"{path}.items"))
            elif k == "anyOf" and isinstance(v, list):
                for idx, choice in enumerate(v):
                    issues.extend(_check_all_objects_forbid_additional_properties(choice, f"{path}.anyOf[{idx}]"))
    return issues


def _build_valid_proposal(now_utc: datetime, *, symbol: str = "NAS100", qty: Decimal = Decimal("0.05")) -> object:
    scope = RunScope(
        account_id="dual-shield-barbell",
        run_id="pr28-run",
        epoch=1,
        build_id="phase8-pr28",
        policy_id="barbell-1pct-valve-v1",
        scenario_id="pr28-test",
        adapter_id="pr28-test-adapter",
    )
    st_ref = StateReference(
        state_id="state-pr28-1",
        scope=scope,
        version=1,
        observed_at=now_utc,
        valid_until=now_utc + timedelta(seconds=30),
        venue_sequence=1,
    )
    intent = ActionIntent(
        intent_id="intent-pr28-open-1",
        scope=scope,
        decision_id="dec-pr28-open-1",
        opportunity_id="opp-pr28-open-1",
        action_ref="open-nas100-1",
        source_state=st_ref,
        kind=ActionKind.OPEN,
        instrument_id=symbol,
        origin=DecisionOrigin.ACTUAL_MODEL,
        created_at=now_utc,
        expires_at=st_ref.valid_until,
        quantity=qty,
        side=Side.BUY,
        limit_price=Decimal("20501.00"),
        stop_price=Decimal("20470.00"),
        take_profit_price=Decimal("20580.00"),
    )
    fact_payload = {"new_risk": True, "management": True, "equity": "10000", "peak_equity": "10000"}
    ev = EvidenceReference(
        evidence_id="ev-pr28-1",
        kind=EvidenceKind.OBSERVATION,
        producer_id="pr28-test",
        content_sha256=content_digest(fact_payload),
        observed_at=now_utc,
    )
    fact = DecisionFact(
        fact_id="fact-pr28-1",
        label="Observed state",
        value=canonical_bytes(fact_payload).decode("utf-8"),
        evidence_ids=("ev-pr28-1",),
    )
    req = DecisionRequest(
        request_id="req-pr28-1",
        opportunity_set_id="set-pr28-1",
        state=st_ref,
        options=(ActionOption("open-nas100-1", "momentum", "M1", "OPEN BUY NAS100", intent),),
        facts=(fact,),
        evidence=(ev,),
    )
    sel = DecisionSelection(
        request_id=req.request_id,
        opportunity_set_id=req.opportunity_set_id,
        source_state_id=st_ref.state_id,
        selected_action_ref="open-nas100-1",
        reason="ID=0open-nas100-1 Strong momentum setup",
        evidence_ids=("ev-pr28-1",),
    )
    res = DecisionResult(
        decision_id="dec-pr28-open-1",
        selection=sel,
        provenance=DecisionProvenance(
            origin=DecisionOrigin.ACTUAL_MODEL,
            adapter_id="pr28-test-adapter",
            request_sha256=content_digest(req),
            response_sha256=content_digest(sel),
            prompt_version="frontier-v2",
            started_at=now_utc,
            completed_at=now_utc,
            model_id="ollama-local",
            model_artifact_sha256="a" * 64,
            inference_receipt_id="rcpt-pr28-1",
        ),
    )

    class _Proposal:
        def __init__(self) -> None:
            self.request = req
            self.result = res
            self.intent = intent

    return _Proposal()



class _PublicIndexQuoteEntry(dict):
    """6-key independent public index provenance mapping (backwards-compatible with tuple indexing during rollout)."""

    def __getitem__(self, key: object) -> object:
        if key == 0:
            return super().__getitem__("bid")
        if key == 1:
            return super().__getitem__("ask")
        return super().__getitem__(key)


class Pr28CompoundingAndPhase8WiringTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="cas_pr28_wt_")
        self.state_dir = Path(self._tmp.name)
        self.now = T_BASE
        self.schema = json.loads(COMPOUNDING_SCHEMA_PATH.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _clock(self) -> datetime:
        return self.now

    def _build_spool_rig(
        self,
        *,
        initial_balance: Decimal = Decimal("5000.00"),
        principal_usd: Decimal = Decimal("5000.00"),
        sub_name: str = "default",
        equity_attestations: dict[str, Decimal] | None = None,
    ) -> tuple[
        Path,
        Mt5SpoolPaperTerminalEmulator,
        DualShieldBrokerRouter,
        ProfitSweepVault,
        AggressionDialStore,
        AutonomousAiTrader,
    ]:
        rig_dir = self.state_dir / sub_name
        rig_dir.mkdir(parents=True, exist_ok=True)
        spool_dir = rig_dir / "spool_hugo"
        peak_store = PeakEquityStore(rig_dir / "peak_equity.sqlite3")
        valve_gate = load_default_forex_valve_gate(peak_equity_store=peak_store)
        emulator = Mt5SpoolPaperTerminalEmulator(
            spool_dir,
            server="Hugosway-Demo3",
            login=7001,
            balance=initial_balance,
            quotes={
                "NAS100": (Decimal("20500.00"), Decimal("20501.00")),
                "US30": (Decimal("43200.00"), Decimal("43202.00")),
                "EURUSD": (Decimal("1.08000"), Decimal("1.08010")),
            },
            broker_channel=BROKER_HUGOSWAY_MT5,
            clock=self._clock,
        )
        emulator.publish_market()
        transport = Mt5SpoolBridgeTransport(
            spool_dir,
            poll_interval_seconds=0.005,
            sleep=emulator.sleep_hook,
            clock=self._clock,
        )
        creds = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=7001, server="Hugosway-Demo3")
        venue = Mt5PaperBrokerVenue(
            broker_id=BROKER_HUGOSWAY_MT5,
            credentials=creds,
            transport=transport,
            valve_gate=valve_gate,
            clock=self._clock,
        )
        venue.connect()

        barbell = BarbellCapitalPolicy(demo_virtual_sleeve=True)
        router = DualShieldBrokerRouter(
            environ={},
            barbell=barbell,
            valve_gate=valve_gate,
            peak_equity_store=peak_store,
            equity_attestations=equity_attestations,
            clock=self._clock,
            index_reference_source=lambda _syms: {
                sym: _PublicIndexQuoteEntry(
                    bid=q[0],
                    ask=q[1],
                    source_provider="YAHOO_STOOQ_PUBLIC",
                    source_broker_id=None,
                    is_independent_public=True,
                    observed_at=self._clock().strftime("%Y-%m-%dT%H:%M:%SZ"),
                )
                for sym, q in emulator.quotes.items()
            },
        )
        router.attach_venue(venue)

        vault = ProfitSweepVault(
            rig_dir / "vault.sqlite3",
            scope_id="dual-shield-barbell",
            initial_capital_usd=principal_usd,
            clock=self._clock,
        )
        quota = DailyQuotaGovernanceStore(rig_dir / "quota.sqlite3")
        dial = AggressionDialStore(rig_dir / "aggression_dial.sqlite3", scope_id="dual-shield-barbell")
        registry = FrontierModelRegistry(environ={})
        trader = AutonomousAiTrader(
            router=router,
            model_registry=registry,
            valve_gate=valve_gate,
            quota_store=quota,
            peak_equity_store=peak_store,
            execution_gate=lambda _inv: None,
            profit_vault=vault,
            aggression_dial=dial,
            risk_gear_mode=RISK_GEAR_AGGRESSIVE,
            initial_capital_usd=principal_usd,
            state_dir=rig_dir,
            clock=self._clock,
        )
        return rig_dir, emulator, router, vault, dial, trader

    def _http_request(
        self,
        srv: LoopbackCockpitServer,
        method: str,
        path: str,
        *,
        bearer: str | None = None,
        body: object | None = None,
    ) -> tuple[int, dict[str, object]]:
        conn = http.client.HTTPConnection("127.0.0.1", srv.bound_port, timeout=5.0)
        try:
            headers: dict[str, str] = {"Host": srv.expected_host_header}
            if bearer is not None:
                headers["Authorization"] = f"Bearer {bearer}"
            payload_bytes: bytes | None = None
            if method == "POST":
                headers["Origin"] = srv.base_url
                raw_json = "{}" if body is None else json.dumps(body)
                payload_bytes = raw_json.encode("utf-8")
                headers["Content-Type"] = "application/json"
                headers["Content-Length"] = str(len(payload_bytes))
            conn.request(method, path, body=payload_bytes, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw)
        finally:
            conn.close()

    def _mint_paired_device_bearer(self, srv: LoopbackCockpitServer, owner_bearer: str) -> str:
        st_code, pair_doc = self._http_request(
            srv, "POST", "/api/pair-code", bearer=owner_bearer, body={"ttl_seconds": 120}
        )
        self.assertEqual(st_code, 200)
        pair_code = str(pair_doc["pair_code"])
        st_ex, ex_doc = self._http_request(
            srv, "POST", "/api/pair-exchange", bearer=None, body={"pair_code": pair_code}
        )
        self.assertEqual(st_ex, 200)
        self.assertEqual(ex_doc["session_scope"], SESSION_SCOPE_DEVICE_READ_EXPLAINER)
        return str(ex_doc["session_token"])

    def test_01_get_compounding_strictly_zero_write_and_schema_valid(self) -> None:
        schema_issues = _check_all_objects_forbid_additional_properties(self.schema)
        self.assertEqual(schema_issues, [])

        rig_dir, _, router, vault, dial, trader = self._build_spool_rig(sub_name="t01")
        # Load both an active news event and an upcoming news event so every nested schema branch is validated
        assert_bridge = trader.phase8_bridge
        if assert_bridge is None:
            self.fail("Expected Phase8LiveTradingBridge to be auto-attached from state_dir")
        assert_bridge._news_shield = NewsShockShield.from_json(
            json.dumps(
                {
                    "updated_at_utc": self.now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "events": [
                        {
                            "event_id": "cpi-live-1",
                            "title": "US CPI YoY",
                            "currency": "USD",
                            "impact": NewsImpact.HIGH.value,
                            "scheduled_utc": (self.now + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "category": "CPI",
                            "source": "pr28-test",
                        },
                        {
                            "event_id": "fomc-upcoming-1",
                            "title": "FOMC Rate Decision",
                            "currency": "USD",
                            "impact": NewsImpact.HIGH.value,
                            "scheduled_utc": (self.now + timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "category": "FOMC",
                            "source": "pr28-test",
                        },
                    ],
                }
            )
        )

        srv = LoopbackCockpitServer(
            repo_root=REPO_ROOT,
            port=0,
            broker_router_reader=router.routing_snapshot,
            autonomous_trader=trader,
            profit_vault=vault,
            aggression_dial=dial,
        )
        srv.start()
        try:
            owner_tok = srv.auth_headers()["Authorization"].split(" ", 1)[1]
            device_tok = self._mint_paired_device_bearer(srv, owner_tok)

            db_files = [
                rig_dir / "compounding.sqlite3",
                rig_dir / "phase8_unified_ledger.sqlite3",
                rig_dir / "vault.sqlite3",
                rig_dir / "aggression_dial.sqlite3",
                rig_dir / "quota.sqlite3",
            ]
            before_versions = {p.name: _sqlite_data_version(p) for p in db_files}

            for _ in range(4):
                st_o, doc_o = self._http_request(srv, "GET", "/api/compounding", bearer=owner_tok)
                self.assertEqual(st_o, 200)
                validate_contract_schema(doc_o, self.schema)
                self.assertTrue(doc_o["owner_controls_allowed"])
                self.assertEqual(doc_o["session_scope"], SESSION_SCOPE_OWNER_FULL)
                self.assertEqual(doc_o["mode"], CompoundingMode.BALANCED_SPLIT_50_50.value)

            for _ in range(3):
                st_d, doc_d = self._http_request(srv, "GET", "/api/compounding", bearer=device_tok)
                self.assertEqual(st_d, 200)
                validate_contract_schema(doc_d, self.schema)
                self.assertFalse(doc_d["owner_controls_allowed"])
                self.assertEqual(doc_d["session_scope"], SESSION_SCOPE_DEVICE_READ_EXPLAINER)

            after_versions = {p.name: _sqlite_data_version(p) for p in db_files}
            self.assertEqual(before_versions, after_versions)
        finally:
            srv.stop()

    def test_02_post_compounding_owner_200_vs_paired_device_403_and_strict_payload(self) -> None:
        _, _, router, vault, dial, trader = self._build_spool_rig(
            initial_balance=Decimal("6000.00"),
            principal_usd=Decimal("5000.00"),
            sub_name="t02",
        )
        srv = LoopbackCockpitServer(
            repo_root=REPO_ROOT,
            port=0,
            broker_router_reader=router.routing_snapshot,
            autonomous_trader=trader,
            profit_vault=vault,
            aggression_dial=dial,
        )
        srv.start()
        try:
            owner_tok = srv.auth_headers()["Authorization"].split(" ", 1)[1]
            device_tok = self._mint_paired_device_bearer(srv, owner_tok)

            # Unauthenticated -> 401
            st_unauth, _ = self._http_request(
                srv, "POST", "/api/compounding", bearer=None, body={"action": "toggle_full_100"}
            )
            self.assertEqual(st_unauth, 401)

            # Paired read-only device -> 403 on ALL compounding mutations (Finding [2])
            for forbidden_body in (
                {"action": "set_mode", "mode": "FULL_COMPOUND_100"},
                {"action": "toggle_full_100"},
                {"action": "acknowledge_principal_withdrawn", "amount_usd": "5000.00"},
            ):
                st_dev, err_dev = self._http_request(
                    srv, "POST", "/api/compounding", bearer=device_tok, body=forbidden_body
                )
                self.assertEqual(st_dev, 403)
                self.assertEqual(err_dev.get("required_scope"), SESSION_SCOPE_OWNER_FULL)

            # Reject unknown keys (strict additionalProperties: false) & floats/bad ratios -> 400
            for bad_body in (
                {"action": "set_mode", "mode": "FULL_COMPOUND_100", "unexpected_key": "nope"},
                {"action": "acknowledge_principal_withdrawn", "amount_usd": "5000.00", "rogue": 1},
                {"action": "set_mode", "mode": "CUSTOM_SPLIT", "custom_sweep_ratio": 0.25},
                {"action": "set_mode", "mode": "CUSTOM_SPLIT", "custom_sweep_ratio": "0.85"},
                {"action": "unknown_action"},
            ):
                st_bad, _ = self._http_request(
                    srv, "POST", "/api/compounding", bearer=owner_tok, body=bad_body
                )
                self.assertEqual(st_bad, 400)

            # Owner sets FULL_COMPOUND_100 -> 200, effective sweep drops to 0.00, vault synced to 0%
            st_ok, updated = self._http_request(
                srv,
                "POST",
                "/api/compounding",
                bearer=owner_tok,
                body={
                    "action": "set_mode",
                    "mode": "FULL_COMPOUND_100",
                    "starting_principal_usd": "5000.00",
                    "house_money_target_usd": "10000.00",
                },
            )
            self.assertEqual(st_ok, 200)
            validate_contract_schema(updated, self.schema)
            self.assertEqual(updated["mode"], "FULL_COMPOUND_100")
            self.assertEqual(updated["effective_vault_sweep_ratio"], "0.00")
            self.assertEqual(updated["retained_compounding_ratio"], "1.00")
            self.assertEqual(vault.snapshot()["sweep_ratio"], "0")

            # Owner sets CUSTOM_SPLIT with custom_sweep_ratio=0.25 -> 200
            st_cust, doc_cust = self._http_request(
                srv,
                "POST",
                "/api/compounding",
                bearer=owner_tok,
                body={"action": "set_mode", "mode": "CUSTOM_SPLIT", "custom_sweep_ratio": "0.25"},
            )
            self.assertEqual(st_cust, 200)
            validate_contract_schema(doc_cust, self.schema)
            self.assertEqual(doc_cust["mode"], "CUSTOM_SPLIT")
            self.assertEqual(doc_cust["effective_vault_sweep_ratio"], "0.25")
            self.assertEqual(vault.snapshot()["sweep_ratio"], "0.25")

            # Owner one-click TOGGLE_FULL_100 flips to FULL_COMPOUND_100 and back to BALANCED_SPLIT_50_50
            st_t1, doc_t1 = self._http_request(
                srv, "POST", "/api/compounding", bearer=owner_tok, body={"action": "toggle_full_100"}
            )
            self.assertEqual(st_t1, 200)
            self.assertEqual(doc_t1["mode"], "FULL_COMPOUND_100")
            st_t2, doc_t2 = self._http_request(
                srv, "POST", "/api/compounding", bearer=owner_tok, body={"action": "toggle_full_100"}
            )
            self.assertEqual(st_t2, 200)
            self.assertEqual(doc_t2["mode"], "BALANCED_SPLIT_50_50")
            self.assertEqual(doc_t2["effective_vault_sweep_ratio"], "0.50")
        finally:
            srv.stop()

    def test_03_full_compound_100_zero_sweep_vs_balanced_50_50_sweep(self) -> None:
        # Case A: FULL_COMPOUND_100 retains 100% ($0.00 swept to Bank Vault)
        _, emu_full, router_full, vault_full, _, trader_full = self._build_spool_rig(
            initial_balance=Decimal("5600.00"),
            principal_usd=Decimal("5000.00"),
            sub_name="t03_full",
        )
        try:
            router_full.venues[BROKER_HUGOSWAY_MT5].probe()
            trader_full.set_compounding_mode(CompoundingMode.FULL_COMPOUND_100)
            trader_full.record_closed_pnl(
                Decimal("600.00"),
                symbol="NAS100",
                ticket="tkt-full-1",
                broker_id=BROKER_HUGOSWAY_MT5,
                now=self.now,
            )
            v_full = vault_full.snapshot()
            self.assertEqual(Decimal(str(v_full["bank_sweep_reserved_usd"])), Decimal("0.00"))
            self.assertEqual(Decimal(str(v_full["retained_trading_usd"])), Decimal("600.00"))
        finally:
            trader_full.close()
            _ = emu_full

        # Case B: BALANCED_SPLIT_50_50 sweeps 50% ($300.00) to Bank Vault & retains 50% ($300.00)
        _, _, router_bal, vault_bal, _, trader_bal = self._build_spool_rig(
            initial_balance=Decimal("5600.00"),
            principal_usd=Decimal("5000.00"),
            sub_name="t03_bal",
        )
        try:
            router_bal.venues[BROKER_HUGOSWAY_MT5].probe()
            trader_bal.record_closed_pnl(
                Decimal("600.00"),
                symbol="NAS100",
                ticket="tkt-bal-1",
                broker_id=BROKER_HUGOSWAY_MT5,
                now=self.now,
            )
            v_bal = vault_bal.snapshot()
            self.assertEqual(Decimal(str(v_bal["bank_sweep_reserved_usd"])), Decimal("300.00"))
            self.assertEqual(Decimal(str(v_bal["retained_trading_usd"])), Decimal("300.00"))
        finally:
            trader_bal.close()

    def test_04_unbreakable_underwater_zero_sweep_invariant(self) -> None:
        _, _, router_uw, vault_uw, _, trader_uw = self._build_spool_rig(
            initial_balance=Decimal("4850.00"),
            principal_usd=Decimal("5000.00"),
            sub_name="t04_uw",
        )
        try:
            router_uw.venues[BROKER_HUGOSWAY_MT5].probe()
            # Even in BALANCED_SPLIT_50_50, underwater equity ($4,850 < $5,000) MUST sweep $0.00
            csnap = trader_uw.compounding_snapshot(now=self.now)
            if csnap is None:
                self.fail("Expected compounding_snapshot")
            self.assertTrue(csnap["underwater"])
            self.assertEqual(csnap["house_money_status"], STATUS_BUILDING_TOWARD_PRINCIPAL)
            self.assertEqual(csnap["effective_vault_sweep_ratio"], "0.00")

            trader_uw.record_closed_pnl(
                Decimal("250.00"),
                symbol="NAS100",
                ticket="tkt-uw-win-1",
                broker_id=BROKER_HUGOSWAY_MT5,
                now=self.now,
            )
            v_uw = vault_uw.snapshot()
            self.assertEqual(Decimal(str(v_uw["bank_sweep_reserved_usd"])), Decimal("0.00"))
        finally:
            trader_uw.close()

    def test_05_house_money_5000_to_10000_milestone_alert_and_principal_withdrawn_ack(self) -> None:
        _, emu_hm, router_hm, vault_hm, dial_hm, trader_hm = self._build_spool_rig(
            initial_balance=Decimal("5000.00"),
            principal_usd=Decimal("5000.00"),
            sub_name="t05_hm",
        )
        srv = LoopbackCockpitServer(
            repo_root=REPO_ROOT,
            port=0,
            broker_router_reader=router_hm.routing_snapshot,
            autonomous_trader=trader_hm,
            profit_vault=vault_hm,
            aggression_dial=dial_hm,
        )
        srv.start()
        try:
            owner_tok = srv.auth_headers()["Authorization"].split(" ", 1)[1]
            device_tok = self._mint_paired_device_bearer(srv, owner_tok)

            # Switch to FULL_COMPOUND_100 at $5,000 start
            st_m, doc_m = self._http_request(
                srv,
                "POST",
                "/api/compounding",
                bearer=owner_tok,
                body={"action": "set_mode", "mode": "FULL_COMPOUND_100"},
            )
            self.assertEqual(st_m, 200)
            self.assertEqual(doc_m["house_money_status"], STATUS_COMPOUNDING_TO_DOUBLE)
            self.assertFalse(doc_m["house_money_ready"])

            # Simulate broker balance doubling to $10,250.00
            emu_hm.balance = Decimal("10250.00")
            emu_hm.publish_market()
            router_hm.venues[BROKER_HUGOSWAY_MT5].probe()

            st_ready, doc_ready = self._http_request(srv, "GET", "/api/compounding", bearer=owner_tok)
            self.assertEqual(st_ready, 200)
            validate_contract_schema(doc_ready, self.schema)
            self.assertTrue(doc_ready["house_money_ready"])
            self.assertEqual(doc_ready["house_money_status"], STATUS_HOUSE_MONEY_READY)
            self.assertEqual(doc_ready["suggested_principal_pullout_usd"], "5000.00")
            self.assertEqual(doc_ready["effective_vault_sweep_ratio"], "0.50")
            m_first = doc_ready["milestones"][0]
            self.assertEqual(m_first["multiple"], 2)
            self.assertTrue(m_first["reached"])

            # Paired device cannot acknowledge principal withdrawal -> 403
            st_forbid, _ = self._http_request(
                srv,
                "POST",
                "/api/compounding",
                bearer=device_tok,
                body={"action": "acknowledge_principal_withdrawn"},
            )
            self.assertEqual(st_forbid, 403)

            # Owner clicks one-click "Mark Original Principal Withdrawn" (omitting amount_usd -> defaults to $5,000.00)
            emu_hm.balance = Decimal("5250.00")
            emu_hm.publish_market()
            router_hm.venues[BROKER_HUGOSWAY_MT5].probe()
            st_ack, doc_ack = self._http_request(
                srv,
                "POST",
                "/api/compounding",
                bearer=owner_tok,
                body={
                    "action": "acknowledge_principal_withdrawn",
                    "post_withdrawal_equity_usd": "5250.00",
                    "note": "Withdrew original $5,000 principal to bank",
                },
            )
            self.assertEqual(st_ack, 200)
            validate_contract_schema(doc_ack, self.schema)
            self.assertTrue(doc_ack["principal_withdrawn"])
            self.assertEqual(doc_ack["principal_withdrawn_usd"], "5000.00")
            self.assertFalse(doc_ack["house_money_ready"])
            self.assertEqual(doc_ack["house_money_status"], STATUS_PLAYING_ON_HOUSE_MONEY)
            self.assertTrue(doc_ack["audit_chain_valid"])
        finally:
            srv.stop()

    def test_06_news_shock_shield_blocks_entry_while_protective_stop_and_close_succeed_under_50ms(self) -> None:
        _, emu_ns, router_ns, _, _, trader_ns = self._build_spool_rig(
            initial_balance=Decimal("10000.00"),
            principal_usd=Decimal("50000.00"),
            sub_name="t06_news",
            equity_attestations={"OANDA_PRACTICE": Decimal("40000.00")},
        )
        try:
            bridge = trader_ns.phase8_bridge
            if bridge is None:
                self.fail("Expected Phase8LiveTradingBridge")

            cpi_time = datetime(2026, 11, 20, 13, 30, 0, tzinfo=timezone.utc)
            bridge._news_shield = NewsShockShield.from_json(
                json.dumps(
                    {
                        "updated_at_utc": self.now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "events": [
                            EconomicEvent(
                                event_id="us-cpi-1",
                                title="US CPI YoY",
                                currency="USD",
                                impact=NewsImpact.HIGH,
                                scheduled_utc=cpi_time,
                                category="CPI",
                                source="pr28-test",
                            ).to_dict()
                        ],
                    }
                )
            )

            # 1) Before CPI blackout (13:20:00Z): open a real protected NAS100 position on Hugo's Way emulator
            venue = router_ns.venues[BROKER_HUGOSWAY_MT5]
            venue.probe()
            open_prop = _build_valid_proposal(self.now, symbol="NAS100", qty=Decimal("0.05"))
            v_view = trader_ns._build_valve_view(
                total_eq=Decimal("50000.00"),
                peak_eq=Decimal("50000.00"),
                new_risk_permission="ALLOWED",
                management_permission="ALLOWED",
            )
            v_dec = trader_ns._valve_gate.require_admissible(open_prop, current_view=v_view, now=self.now)
            open_order = OrderIntent(
                order_id="ord-pre-cpi-1",
                action_ref="open-nas100-1",
                kind=ActionKind.OPEN,
                symbol="NAS100",
                quantity_units=Decimal("0.05"),
                side=Side.BUY,
                stop_price=Decimal("20470.00"),
                limit_price=Decimal("20501.00"),
                take_profit_price=Decimal("20580.00"),
            )
            exec_res = router_ns.execute_open(open_order, valve_decision=v_dec)
            tkt = str(exec_res.result.receipt.position_ticket)
            trader_ns._open_position_meta[tkt] = {
                "ticket": tkt,
                "broker_id": BROKER_HUGOSWAY_MT5,
                "symbol": "NAS100",
                "side": "BUY",
                "volume_lots": "0.05",
                "entry_price": "20501",
                "stop_loss": "20470",
                "take_profit": "20580",
                "profit": "0",
                "protection_stage": "INITIAL_SL",
            }
            self.assertEqual(len(venue.positions), 1)

            # 2) Advance clock to exact CPI release (13:30:00Z) inside [-5m, +5m] blackout!
            self.now = cpi_time
            # Feed momentum ticks on US30 that would otherwise trigger a fast-tick entry setup
            for step in range(5):
                b = Decimal("43200.00") + Decimal(step * 8)
                a = b + Decimal("1.50")
                trader_ns._tick_history["US30"].append((b, a))
            cyc_report = trader_ns.run_fast_tick_cycle(
                mt5_quotes={
                    "NAS100": (Decimal("20500.00"), Decimal("20501.00")),
                    "US30": (Decimal("43240.00"), Decimal("43241.50")),
                },
                now=cpi_time,
            )
            self.assertEqual(cyc_report["action"], "WAIT")
            self.assertIn("NEW_ENTRY_PAUSED_NEWS_WINDOW", str(cyc_report["reason"]))
            self.assertEqual(len(venue.positions), 1)

            # 3) At exact CPI release (13:30:00Z), NAS100 spikes in our favor -> 50ms stop protection MUST succeed!
            emu_ns.set_quote("NAS100", Decimal("20535.00"), Decimal("20536.00"))
            emu_ns.publish_market()
            t0_prot = time.perf_counter()
            prot_actions = trader_ns.protect_open_positions(
                quotes={"NAS100": (Decimal("20535.00"), Decimal("20536.00"))},
                now=cpi_time,
            )
            prot_ms = (time.perf_counter() - t0_prot) * 1000.0
            self.assertEqual(len(prot_actions), 1)
            self.assertIn(prot_actions[0]["stage"], ("BREAKEVEN_LOCKED", "TRAILING_ACTIVE"))
            # Verify CRITICAL_PROTECTION lane latency < 50ms even at exact CPI release second
            from cas_forex_revamp.risk.news_shock_shield import TradeActionType
            direct_prot = bridge.dispatch_protective_action(
                broker_id=BROKER_HUGOSWAY_MT5,
                symbol="NAS100",
                action=TradeActionType.TRAIL_STOP,
                order_id="prot-check-cpi",
                position_ticket=tkt,
                side=Side.BUY,
                quantity_lots=Decimal("0.05"),
                price=Decimal("20535.00"),
                stop_loss=Decimal(str(prot_actions[0]["new_stop_loss"])),
                reason="CPI <50ms lane check",
                now_utc=cpi_time,
            )
            self.assertTrue(direct_prot.allowed)
            self.assertLess(direct_prot.elapsed_ms, Decimal("50.000"))
            self.assertLess(prot_ms, 2000.0)
            bridge.flush(timeout=2.0)
            self.assertGreaterEqual(bridge.event_bus.metrics()["published_count"], 1)

            # 4) Still inside CPI blackout (13:31:00Z), emergency_close_all MUST succeed unconditionally!
            self.now = cpi_time + timedelta(minutes=1)
            emu_ns.publish_market()
            close_snap = trader_ns.emergency_close_all(reason="CPI protective exit", now=self.now)
            self.assertIn(tkt, close_snap["closed_tickets"])
            venue.probe()
            self.assertEqual(len(venue.positions), 0)
            bridge.flush(timeout=2.0)
            ledger_snap = bridge.ledger.snapshot(now_utc=self.now)
            self.assertGreaterEqual(ledger_snap.daily_closed_trades, 1)
        finally:
            trader_ns.close()

    def test_07_immutable_constitutional_ceilings_and_zero_leaked_threads(self) -> None:
        threads_before = {
            t.name for t in threading.enumerate() if t.is_alive() and "phase8-bridge" in t.name
        }
        _, _, router, vault, dial, trader = self._build_spool_rig(
            initial_balance=Decimal("10000.00"),
            principal_usd=Decimal("5000.00"),
            sub_name="t07_ceil",
        )
        srv = LoopbackCockpitServer(
            repo_root=REPO_ROOT,
            port=0,
            broker_router_reader=router.routing_snapshot,
            autonomous_trader=trader,
            profit_vault=vault,
            aggression_dial=dial,
        )
        srv.start()
        try:
            bridge = trader.phase8_bridge
            ctrl = trader.compounding_controller
            if bridge is None or ctrl is None:
                self.fail("Expected Phase8LiveTradingBridge and CompoundingAndMilestoneController")

            # 1) > 1.00% per-trade stop-loss risk refused by both controller & Phase8LiveTradingBridge
            b_over_risk = ctrl.compute_compounding_sizing_budget(
                current_equity_usd=Decimal("10000.00"),
                risk_pct=Decimal("1.01"),
            )
            self.assertFalse(b_over_risk.allowed)
            self.assertEqual(b_over_risk.reason_code, "CONSTITUTIONAL_STOP_RISK_EXCEEDED")

            prop = _build_valid_proposal(self.now)
            acct_state = AccountMarginState(
                account_id="dual-shield-barbell",
                balance=Decimal("10000.00"),
                equity=Decimal("10000.00"),
                used_margin=Decimal("0.00"),
                free_margin=Decimal("10000.00"),
                peak_equity=Decimal("10000.00"),
            )
            q_snap = QuoteSnapshot(
                symbol="NAS100",
                bid=Decimal("20500.00"),
                ask=Decimal("20501.00"),
                timestamp_utc=self.now,
            )
            d_over_risk = bridge.evaluate_pre_entry(
                broker_id=BROKER_HUGOSWAY_MT5,
                symbol="NAS100",
                side=Side.BUY,
                equity_usd=Decimal("10000.00"),
                stop_distance_points=Decimal("30.00"),
                risk_pct=Decimal("1.25"),
                quote=q_snap,
                account_state=acct_state,
                proposal=prop,
                now_utc=self.now,
            )
            self.assertFalse(d_over_risk.allowed)
            self.assertEqual(d_over_risk.reason_code, "CONSTITUTIONAL_STOP_RISK_EXCEEDED")

            # 2) >= 10.00% (0.10) drawdown refused by both controller & Phase8LiveTradingBridge
            d_over_dd = bridge.evaluate_pre_entry(
                broker_id=BROKER_HUGOSWAY_MT5,
                symbol="NAS100",
                side=Side.BUY,
                equity_usd=Decimal("9000.00"),
                stop_distance_points=Decimal("30.00"),
                risk_pct=Decimal("0.50"),
                quote=q_snap,
                account_state=acct_state,
                proposal=prop,
                drawdown_pct=Decimal("0.10"),
                now_utc=self.now,
            )
            self.assertFalse(d_over_dd.allowed)
            self.assertEqual(d_over_dd.reason_code, "CONSTITUTIONAL_DRAWDOWN_LIMIT_REACHED")

            # 3) BarbellCapitalPolicy / AutonomousAiTrader rejects > 1.00% stop-loss risk ceiling
            with self.assertRaises(ContractError):
                bad_barbell = BarbellCapitalPolicy(
                    max_stop_loss_equity_risk_pct=Decimal("1.50"),
                    demo_virtual_sleeve=True,
                )
                bad_router = DualShieldBrokerRouter(
                    environ={},
                    barbell=bad_barbell,
                    valve_gate=trader._valve_gate,
                    peak_equity_store=trader._peak_store,
                )
                AutonomousAiTrader(
                    router=bad_router,
                    model_registry=FrontierModelRegistry(environ={}),
                    valve_gate=trader._valve_gate,
                    execution_gate=lambda _inv: None,
                )
        finally:
            srv.stop()

        threads_after = {
            t.name for t in threading.enumerate() if t.is_alive() and "phase8-bridge" in t.name
        }
        self.assertEqual(threads_after - threads_before, set())
        self.assertTrue(trader.phase8_bridge.event_bus.metrics()["closed"])


if __name__ == "__main__":
    unittest.main()
