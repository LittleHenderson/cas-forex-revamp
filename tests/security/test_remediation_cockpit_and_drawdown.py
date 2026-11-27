"""Security remediation regression suite for Findings [3] (Drawdown Gate) and [9] (Authenticated Loopback Cockpit).

All tests are deterministic `unittest.TestCase` methods with zero skips and zero external network traffic.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import http.client
import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[2]
for _p in ('src', '', 'tests/integration'):
    _c = str((_ROOT / _p).resolve())
    if _c not in sys.path:
        sys.path.insert(0, _c)
import tempfile
from types import SimpleNamespace
import unittest
import urllib.error
import urllib.request

from cas_forex_revamp.composition.continuous_driver import SyntheticClock, _admit, _assemble, _control, _propose
from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer
from cas_forex_revamp.composition.r6_runtime import CaseRuntime
from cas_forex_revamp.composition.read_service import DecisionReadService
from cas_forex_revamp.composition.synthetic_fixture import continuous_a_fixture
from cas_forex_revamp.composition.ui_service import ScopedUIService
from cas_forex_revamp.contracts import ActionKind, ContractError, ControlKind, DecisionOrigin, DecisionProvenance, DecisionResult, DecisionSelection, Side, content_digest
from cas_forex_revamp.operator.decisions import DecisionProposal
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    PeakEquityStore,
    ValveRefusalError,
    compute_drawdown_pct,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.dual_shield_router import (
    BarbellCapitalPolicy,
    BarbellPolicyRefusalError,
    DualShieldBrokerRouter,
    OandaQuoteTruthOracle,
)
from cas_forex_revamp.venue.live_market_stream import MarketStreamEnvelope
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_OANDA_PRACTICE,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    OrderIntent,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
T0 = datetime(2026, 11, 16, 15, 0, tzinfo=timezone.utc)
D = Decimal


def _make_proposal(
    *,
    kind: ActionKind | None,
    action_ref: str | None = "act-sec-1",
    quantity: Decimal | None = D("10000"),
    stop_price: Decimal | None = D("1.09500"),
    side: Side | None = Side.BUY,
    account_id: str = "acct-dd-1",
    run_id: str = "run-dd-1",
):
    scope = SimpleNamespace(account_id=account_id, run_id=run_id)
    state = SimpleNamespace(scope=scope, observed_at=T0, valid_until=T0 + timedelta(minutes=5))
    request = SimpleNamespace(
        request_id="req-dd-1",
        facts=(),
        evidence=(SimpleNamespace(evidence_id="ev-dd-1"),),
        state=state,
    )
    if kind is None:
        intent = None
        sel_ref = None
    else:
        intent = SimpleNamespace(
            intent_id="intent-dd-1",
            action_ref=action_ref,
            kind=kind,
            instrument_id="EURUSD",
            quantity=quantity if kind in (ActionKind.OPEN, ActionKind.ADD, ActionKind.REDUCE, ActionKind.CLOSE) else None,
            side=side if kind in (ActionKind.OPEN, ActionKind.ADD) else None,
            stop_price=stop_price if kind in (ActionKind.OPEN, ActionKind.ADD, ActionKind.AMEND_STOP) else None,
            limit_price=None,
            target_id=None if kind is ActionKind.OPEN else "pos-1",
        )
        sel_ref = action_ref
    selection = SimpleNamespace(
        evidence_ids=("ev-dd-1",) if kind is not None else (),
        reason="Disciplined setup with current evidence",
        selected_action_ref=sel_ref,
    )
    return SimpleNamespace(request=request, result=SimpleNamespace(selection=selection), intent=intent)


def _base_policy(max_dd: str = "0.10") -> dict[str, object]:
    return {
        "new_risk_permission": "ALLOWED",
        "management_permission": "ALLOWED",
        "max_entry_quantity": "500000",
        "max_drawdown_pct": max_dd,
        "accounting_required": ["balance", "equity", "available_margin", "position_inventory"],
    }


class DrawdownGateRemediationTests(unittest.TestCase):
    """Finding [3]: Durable peak-equity & max-drawdown gate across Valve, CaseRuntime, and DualShield."""

    def test_open_and_add_refused_at_or_above_drawdown_threshold_while_wait_reduce_close_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = PeakEquityStore(Path(tmp) / "peak.sqlite3")
            gate = load_default_forex_valve_gate(max_drawdown_pct=D("0.10"), peak_equity_store=store)
            self.assertEqual(gate.controller.parameter_count, 161)

            # Seed high-water mark at 100,000 (0% drawdown -> OPEN admitted)
            view_clean = {
                "account_id": "acct-dd",
                "balance": "100000",
                "equity": "100000",
                "peak_equity": "100000",
                "available_margin": "95000",
                "position_inventory": [],
            }
            dec_ok = gate.require_admissible(
                _make_proposal(kind=ActionKind.OPEN),
                current_view=view_clean,
                policy=_base_policy("0.10"),
                now=T0 + timedelta(seconds=1),
            )
            self.assertTrue(dec_ok.admitted)

            # Exact 10.00% drawdown (equity = 90,000 vs peak 100,000) and 12.00% drawdown (equity = 88,000)
            for eq in ("90000", "88000"):
                view_dd = {**view_clean, "equity": eq}
                for entry_kind in (ActionKind.OPEN, ActionKind.ADD):
                    with self.assertRaises(ValveRefusalError) as ctx:
                        gate.require_admissible(
                            _make_proposal(kind=entry_kind),
                            current_view=view_dd,
                            policy=_base_policy("0.10"),
                            now=T0 + timedelta(seconds=1),
                        )
                    self.assertIn("MAX_DRAWDOWN_EXCEEDED", ctx.exception.decision.hard_veto_reasons)

            # WAIT, REDUCE, CLOSE, and tightening AMEND_STOP remain permitted during 12% drawdown
            view_dd = {
                **view_clean,
                "equity": "88000",
                "position_inventory": [{"ticket": "pos-1", "symbol": "EURUSD", "side": "BUY", "stop_loss": "1.09400"}],
            }
            wait_dec = gate.require_admissible(
                _make_proposal(kind=None),
                current_view=view_dd,
                policy=_base_policy("0.10"),
                now=T0 + timedelta(seconds=1),
            )
            self.assertTrue(wait_dec.admitted)
            self.assertEqual(wait_dec.valve_mode, "WAIT_BYPASS")

            for mgmt_kind in (ActionKind.REDUCE, ActionKind.CLOSE, ActionKind.AMEND_STOP):
                mgmt_dec = gate.require_admissible(
                    _make_proposal(kind=mgmt_kind),
                    current_view=view_dd,
                    policy=_base_policy("0.10"),
                    now=T0 + timedelta(seconds=1),
                )
                self.assertTrue(mgmt_dec.admitted, msg=f"{mgmt_kind} should remain allowed in drawdown")

    def test_restart_cannot_clear_high_water_mark_without_authenticated_owner_rearm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "durable-peak.sqlite3"
            store1 = PeakEquityStore(db_path)
            self.assertFalse(db_path.exists())  # Inert on construction
            p1 = store1.observe_equity("acct-r:run-1", current_equity=D("125000"), opening_balance=D("100000"), now=T0)
            self.assertEqual(p1, D("125000"))

            # Simulated process restart: new store + new gate over same SQLite file with lower equity & lower opening_balance
            store2 = PeakEquityStore(db_path)
            gate2 = load_default_forex_valve_gate(max_drawdown_pct=D("0.10"), peak_equity_store=store2)
            p2 = store2.observe_equity("acct-r:run-1", current_equity=D("110000"), opening_balance=D("110000"), now=T0)
            self.assertEqual(p2, D("125000"))  # High-water preserved across restart (drawdown = 12%)

            view_after_restart = {
                "balance": "110000",
                "equity": "110000",
                "available_margin": "105000",
                "position_inventory": [],
            }
            with self.assertRaises(ValveRefusalError) as blocked:
                gate2.require_admissible(
                    _make_proposal(kind=ActionKind.OPEN, account_id="acct-r", run_id="run-1"),
                    current_view=view_after_restart,
                    policy=_base_policy("0.10"),
                    now=T0 + timedelta(seconds=2),
                )
            self.assertIn("MAX_DRAWDOWN_EXCEEDED", blocked.exception.decision.hard_veto_reasons)

            # Unauthenticated or forged re-arm attempts fail closed
            with self.assertRaises(ContractError):
                store2.rearm_after_drawdown(
                    "acct-r:run-1",
                    new_peak_equity=D("110000"),
                    owner_verifier=None,
                    owner_request_id="unauth-1",
                    now=T0,
                )
            bad_verifier = SimpleNamespace(verify_drawdown_rearm=lambda **_: False)
            with self.assertRaises(ContractError):
                store2.rearm_after_drawdown(
                    "acct-r:run-1",
                    new_peak_equity=D("110000"),
                    owner_verifier=bad_verifier,
                    owner_request_id="forged-1",
                    now=T0,
                )
            self.assertEqual(store2.read_peak("acct-r:run-1"), D("125000"))

            # Authenticated owner verifier re-arms peak_equity to 110,000 -> new OPEN admitted
            good_verifier = SimpleNamespace(
                verify_drawdown_rearm=lambda *, scope_id, request_id, new_peak_equity, now: (
                    scope_id == "acct-r:run-1" and request_id == "owner-rearm-1" and new_peak_equity == D("110000")
                )
            )
            rearmed = store2.rearm_after_drawdown(
                "acct-r:run-1",
                new_peak_equity=D("110000"),
                owner_verifier=good_verifier,
                owner_request_id="owner-rearm-1",
                now=T0 + timedelta(seconds=3),
            )
            self.assertEqual(rearmed, D("110000"))
            admitted = gate2.require_admissible(
                _make_proposal(kind=ActionKind.OPEN, account_id="acct-r", run_id="run-1"),
                current_view=view_after_restart,
                policy=_base_policy("0.10"),
                now=T0 + timedelta(seconds=4),
            )
            self.assertTrue(admitted.admitted)

    def test_missing_drawdown_accounting_fails_closed(self) -> None:
        gate = load_default_forex_valve_gate(max_drawdown_pct=D("0.10"))
        bad_views = [
            None,
            {"balance": "100000", "equity": None, "available_margin": "90000", "position_inventory": []},
            {"balance": "100000", "equity": "100000", "peak_equity": None, "available_margin": "90000", "position_inventory": []},
            {"balance": "100000", "equity": "100000", "peak_equity": "UNAVAILABLE", "available_margin": "90000", "position_inventory": []},
        ]
        for bad_view in bad_views:
            with self.assertRaises(ValveRefusalError) as ctx:
                gate.require_admissible(
                    _make_proposal(kind=ActionKind.OPEN),
                    current_view=bad_view,
                    policy=_base_policy("0.10"),
                    now=T0 + timedelta(seconds=1),
                )
            self.assertIn("MISSING_DRAWDOWN_ACCOUNTING", ctx.exception.decision.hard_veto_reasons)

        # Invalid max_drawdown_pct in policy also fails closed
        with self.assertRaises(ValveRefusalError) as bad_pol:
            gate.require_admissible(
                _make_proposal(kind=ActionKind.OPEN),
                current_view={"balance": "100000", "equity": "100000", "peak_equity": "100000", "available_margin": "90000", "position_inventory": []},
                policy={**_base_policy(), "max_drawdown_pct": None},
                now=T0 + timedelta(seconds=1),
            )
        self.assertIn("MISSING_DRAWDOWN_ACCOUNTING", bad_pol.exception.decision.hard_veto_reasons)

    def test_case_runtime_and_dual_shield_enforce_drawdown_and_owner_rearm(self) -> None:
        from r6_development_fixture import Clock, case, option, step

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dd_store = PeakEquityStore(root / "shared-dd.sqlite3")
            gate = load_default_forex_valve_gate(max_drawdown_pct=D("0.10"), peak_equity_store=dd_store)
            c = case([step(options=[option(1, "OPEN", quantity="10")])])
            clk = Clock()
            rt = CaseRuntime(
                c,
                directory=root / "case-1",
                execution_id="sec-dd",
                build_id="b1",
                adapter=None,
                clock=clk,
                valve_gate=gate,
                peak_equity_store=dd_store,
            )
            # Pre-seed peak at 12,000 while venue starts at 10,000 -> 16.67% drawdown
            dd_store.observe_equity(rt._drawdown_scope_id, current_equity=D("12000"), opening_balance=D("12000"), now=clk())
            rt.initialize()
            req, _, binding, view, _ = rt.prepare(c["steps"][0])
            sel = DecisionSelection(req.request_id, req.opportunity_set_id, req.state.state_id, req.options[0].action_ref, "Entry", (req.evidence[0].evidence_id,))
            prov = DecisionProvenance(DecisionOrigin.ACTUAL_MODEL, "test", content_digest(req), content_digest(sel), "v1", clk(), clk(), "qwen3:0.6b", "c" * 64, "rcpt-1")
            prop = DecisionProposal(req, DecisionResult(req.options[0].intent.decision_id, sel, prov), req.options[0].intent)
            with self.assertRaises(ValveRefusalError) as r6_err:
                rt.admit_dispatch(prop, binding, view, "cmd-dd-blocked")
            self.assertIn("MAX_DRAWDOWN_EXCEEDED", r6_err.exception.decision.hard_veto_reasons)

            # Owner rearm resets high-water to current 10,000
            new_peak = rt.rearm_drawdown(owner_request_id="owner-rearm-r6")
            self.assertEqual(new_peak, D("10000"))
            self.assertEqual(compute_drawdown_pct(D("10000"), new_peak), D("0"))

        # DualShieldBrokerRouter drawdown refusal
        with tempfile.TemporaryDirectory() as tmp2:
            spool = Path(tmp2) / "spool"
            quotes = {"EURUSD": (D("1.10000"), D("1.10010"))}
            emu = Mt5SpoolPaperTerminalEmulator(spool / "hugosway_mt5", server="Hugosway-Demo", login=7001234, quotes=quotes, balance=D("8000"))
            emu.publish_market()
            router = DualShieldBrokerRouter(
                environ={"CAS_FOREX_MT5_TRANSPORT_MODE": "SPOOL_BRIDGE", "CAS_FOREX_MT5_SPOOL_DIR": str(spool), "CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234"},
                valve_gate=load_default_forex_valve_gate(),
                oracle=OandaQuoteTruthOracle.from_static_quotes(quotes),
                barbell=BarbellCapitalPolicy(max_drawdown_pct=D("0.10")),
                equity_attestations={BROKER_OANDA_PRACTICE: D("80000")},
                initial_peak_equity=D("100000"),  # Current total = 88,000 vs initial peak 100,000 -> 12% drawdown
                transport_factory=lambda b, m, r: Mt5SpoolBridgeTransport(Path(r) / b.lower(), sleep=emu.sleep_hook, poll_interval_seconds=0.01),
                clock=lambda: T0 + timedelta(seconds=1),
            )
            router.activate_all()
            order = OrderIntent(
                order_id="ds-dd-1",
                action_ref="act-dd-1",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
            )
            v_ok = load_default_forex_valve_gate().require_admissible(
                _make_proposal(kind=ActionKind.OPEN, action_ref="act-dd-1"),
                current_view={"balance": "100000", "equity": "100000", "peak_equity": "100000", "available_margin": "95000", "position_inventory": []},
                policy=_base_policy("0.10"),
                now=T0 + timedelta(seconds=1),
            )
            with self.assertRaises(BarbellPolicyRefusalError) as ds_err:
                router.execute_open(order, valve_decision=v_ok)
            self.assertEqual(ds_err.exception.reason, "MAX_DRAWDOWN_EXCEEDED")


class LoopbackCockpitAuthRemediationTests(unittest.TestCase):
    """Findings [1] & [9]: Per-launch Bearer-only auth (zero cookies), pre-body Host/Origin checks, and session rotation."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = continuous_a_fixture()
        self.clock = SyntheticClock(self.fixture.started_at)
        self.app, self.owner, self.journal = _assemble(self.root, self.fixture.scope, self.clock)
        self.journal.initialize(create=True)
        self.app.venue.initialize(
            self.fixture.scope.key,
            opening_balance=self.fixture.opening_balance,
            instruments=self.fixture.instruments,
            now=self.clock(),
            scenario=self.fixture.venue_scenario,
        )
        self.app.core.initialize(create=True)
        self.clock.now = self.fixture.market[0].available_at
        self.app.wiring.advance_market(self.fixture.market[0])
        _control(self.app, self.owner, self.journal, self.clock, ControlKind.STOP_AUTOMATION, "init-stop")
        schema = (REPO_ROOT / "docs/contracts/decision-read.schema.json").read_bytes()
        self.reader = DecisionReadService(
            scope=self.fixture.scope,
            core=self.app.core,
            venue=self.app.venue,
            journal=self.journal,
            clock=self.clock,
            schema_bytes=schema,
            schema_sha256=sha256(schema).hexdigest(),
            instruments=self.fixture.instruments,
        )
        self.ui = ScopedUIService(app=self.app, owner=self.owner, journal=self.journal, reader=self.reader, clock=self.clock)
        self.stream = MarketStreamEnvelope.from_json_bytes((REPO_ROOT / "docs/contracts/initial-market-stream.json").read_bytes())
        self.server = LoopbackCockpitServer(
            repo_root=REPO_ROOT,
            host="127.0.0.1",
            port=0,
            ui_service=self.ui,
            market_stream_reader=self.stream.to_wire_dict,
            broker_router_reader=lambda: {"schema": "cas-forex.broker-routing/2", "demo_only": True, "live_trading_locked": True, "chain": []},
        )
        self.base_url = self.server.start()
        self.addCleanup(self.server.stop)

    def _raw_http(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> tuple[int, dict[str, str], bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.server.bound_port, timeout=5)
        try:
            hdrs = dict(headers or {})
            if "Host" not in hdrs:
                hdrs["Host"] = self.server.expected_host_header
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read(4096)
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
        finally:
            conn.close()

    def test_all_protected_routes_reject_missing_or_wrong_token(self) -> None:
        get_routes = (
            "/api/boot",
            "/api/cockpit",
            "/api/decision-read",
            "/api/market-stream",
            "/api/market-events",
            "/api/broker-routing",
        )
        for route in get_routes:
            st_none, hdr_none, _ = self._raw_http("GET", route)
            self.assertEqual(st_none, 401, route)
            self.assertIn("bearer", hdr_none.get("www-authenticate", "").lower())
            st_bad, _, _ = self._raw_http("GET", route, headers={"Authorization": "Bearer wrong-" + "x" * 40})
            self.assertEqual(st_bad, 401, route)

        post_routes = (
            "/api/resolve-evidence",
            "/api/prepare-control",
            "/api/request-control",
            "/api/read-control",
            "/api/prepare-close",
            "/api/request-reviewed-close",
            "/api/read-command",
        )
        payload = b'{"command_id":"cmd-1"}'
        for route in post_routes:
            st_none, _, _ = self._raw_http(
                "POST",
                route,
                headers={"Content-Type": "application/json", "Content-Length": str(len(payload))},
                body=payload,
            )
            self.assertEqual(st_none, 401, route)
            st_bad, _, _ = self._raw_http(
                "POST",
                route,
                headers={
                    "Authorization": "Bearer bad-" + "y" * 40,
                    "Content-Type": "application/json",
                    "Content-Length": str(len(payload)),
                },
                body=payload,
            )
            self.assertEqual(st_bad, 401, route)

        # Unauthenticated /api/health discloses zero scope/bridge/stream details
        st_h, _, raw_h = self._raw_http("GET", "/api/health")
        self.assertEqual(st_h, 200)
        doc_h = json.loads(raw_h.decode("utf-8"))
        self.assertFalse(doc_h["authenticated"])
        self.assertNotIn("bridge_attached", doc_h)
        self.assertNotIn("session_epoch", doc_h)

    def test_foreign_host_and_origin_rejected_before_body_read(self) -> None:
        # Declare an oversized Content-Length (> 256 KiB) with NO body sent: if the server tried to
        # read or parse the body before checking Host/Origin, it would either block or return 400.
        # Returning 403 immediately proves pre-body rejection.
        auth = f"Bearer {self.server.auth_token}"
        bad_envelopes = [
            {"Host": "evil.rebind.example", "Authorization": auth, "Content-Length": "999999"},
            {"Host": f"localhost:{self.server.bound_port}", "Authorization": auth, "Content-Length": "999999"},
            {"Host": "127.0.0.1:1", "Authorization": auth, "Content-Length": "999999"},
            {"Host": self.server.expected_host_header, "Origin": "https://evil.example", "Authorization": auth, "Content-Length": "999999"},
            {"Host": self.server.expected_host_header, "Origin": "null", "Authorization": auth, "Content-Length": "999999"},
            {"Host": self.server.expected_host_header, "Sec-Fetch-Site": "cross-site", "Authorization": auth, "Content-Length": "999999"},
        ]
        for hdrs in bad_envelopes:
            status, _, _ = self._raw_http("POST", "/api/prepare-control", headers=hdrs, body=b"")
            self.assertEqual(status, 403, msg=f"Expected pre-body 403 for headers={hdrs}")

    def test_bearer_only_bootstrap_emits_no_cookies_and_rejects_cookie_auth(self) -> None:
        # Wrong bootstrap token is rejected and never emits Set-Cookie
        st_bad, hdr_bad, _ = self._raw_http("GET", "/ui/index.html?token=wrong-token")
        self.assertEqual(st_bad, 401)
        self.assertNotIn("set-cookie", hdr_bad)

        # Primary bearer in ?token= URL is forbidden (401); single-use ?pair_code= serves UI with zero cookies ([1], [2])
        st_tok_forbidden, _, _ = self._raw_http("GET", f"/ui/index.html?token={self.server.auth_token}")
        self.assertEqual(st_tok_forbidden, 401)
        pair_doc = self.server.mint_pairing_code()
        st_ok, hdr_ok, _ = self._raw_http("GET", f"/ui/index.html?pair_code={pair_doc['pair_code']}")
        self.assertEqual(st_ok, 200)
        self.assertNotIn("set-cookie", hdr_ok)

        # Cookie-only GET must be rejected (401) even if holding the server token
        cookie_hdr = f"cas_forex_cockpit_token={self.server.auth_token}"
        st_cookie, _, _ = self._raw_http("GET", "/api/boot", headers={"Cookie": cookie_hdr})
        self.assertEqual(st_cookie, 401)

        # Authorization: Bearer works on loopback
        auth_hdr = f"Bearer {self.server.auth_token}"
        st_get, _, raw_boot = self._raw_http("GET", "/api/boot", headers={"Authorization": auth_hdr})
        self.assertEqual(st_get, 200)
        boot = json.loads(raw_boot.decode("utf-8"))

        # Bearer POST with non-loopback Origin is rejected (403)
        prep_body = json.dumps({
            "request_id": "bearer-pause-1",
            "scope": boot["scope"],
            "control": "PAUSE_NEW_RISK",
            "expected_generation": boot["fence_generation"],
        }).encode("utf-8")
        st_bad_origin, _, _ = self._raw_http(
            "POST",
            "/api/prepare-control",
            headers={
                "Authorization": auth_hdr,
                "Origin": "https://evil.example",
                "Content-Type": "application/json",
                "Content-Length": str(len(prep_body)),
            },
            body=prep_body,
        )
        self.assertEqual(st_bad_origin, 403)

        # Bearer POST with exact loopback Origin succeeds
        st_with_origin, _, _ = self._raw_http(
            "POST",
            "/api/prepare-control",
            headers={
                "Authorization": auth_hdr,
                "Origin": self.base_url,
                "Content-Type": "application/json",
                "Content-Length": str(len(prep_body)),
            },
            body=prep_body,
        )
        self.assertEqual(st_with_origin, 200)

    def test_token_rotation_and_restart_invalidate_prior_prepared_control_and_close(self) -> None:
        # Open a position so reviewed close can also be prepared
        _control(self.app, self.owner, self.journal, self.clock, ControlKind.RESUME_NEW_RISK, "resume-for-open")
        prop = _propose(self.app, self.journal, self.clock, "sec-open-1")
        _admit(self.app, self.journal, self.clock, prop, self.fixture.entry_command_id)
        self.app.wiring.dispatch_once()
        for quote in self.fixture.market[1:3]:
            self.clock.now = quote.available_at
            self.app.wiring.advance_market(quote)
        pos = self.app.venue.snapshot(self.fixture.scope.key, now=self.clock()).positions[0]

        tok1 = self.server.auth_token
        epoch1 = self.server.session_epoch

        def rpc(method: str, path: str, token: str, payload: dict | None = None) -> tuple[int, dict]:
            body = b"" if payload is None else json.dumps(payload).encode("utf-8")
            hdrs = {"Authorization": f"Bearer {token}"}
            if payload is not None:
                hdrs["Content-Type"] = "application/json"
                hdrs["Content-Length"] = str(len(body))
            st, _, raw = self._raw_http(method, path, headers=hdrs, body=body)
            return st, json.loads(raw.decode("utf-8"))

        st_b, boot1 = rpc("GET", "/api/boot", tok1)
        self.assertEqual(st_b, 200)
        self.assertEqual(boot1["session_epoch"], epoch1)

        # Prepare both a control and a reviewed close under session 1
        st_pc, prepared_ctrl = rpc("POST", "/api/prepare-control", tok1, {
            "request_id": "rot-ctrl-1",
            "scope": boot1["scope"],
            "control": "PAUSE_NEW_RISK",
            "expected_generation": boot1["fence_generation"],
        })
        self.assertEqual(st_pc, 200)

        state = self.app.core.current_state(self.fixture.scope.key, now=self.clock())
        st_px, preview_close = rpc("POST", "/api/prepare-close", tok1, {
            "owner_request_id": "rot-close-1",
            "command_id": "rot-close-cmd-1",
            "scope": boot1["scope"],
            "source_state_id": state.state_id,
            "position_id": pos.position_id,
            "position_version": pos.version,
            "quantity": str(pos.quantity),
            "quantity_unit": "BASE_UNITS",
        })
        self.assertEqual(st_px, 200)

        # Rotate token (same as server restart): old token is 401, and even with new token prior prepared objects are rejected!
        tok2 = self.server.rotate_auth_token()
        self.assertNotEqual(tok1, tok2)
        self.assertNotEqual(epoch1, self.server.session_epoch)

        st_old, _ = rpc("POST", "/api/request-control", tok1, prepared_ctrl)
        self.assertEqual(st_old, 401)

        st_stale_ctrl, err_ctrl = rpc("POST", "/api/request-control", tok2, prepared_ctrl)
        self.assertEqual(st_stale_ctrl, 400)
        self.assertIn("not prepared", err_ctrl["error"])

        close_submit = {k: preview_close[k] for k in ("preview_id", "owner_request_id", "command_id", "scope", "intent_sha256")}
        st_stale_close, err_close = rpc("POST", "/api/request-reviewed-close", tok2, close_submit)
        self.assertEqual(st_stale_close, 400)
        self.assertIn("not reviewed", err_close["error"])

        # Re-preparing under the new rotated session succeeds cleanly
        _, boot2 = rpc("GET", "/api/boot", tok2)
        st_fresh_prep, fresh_ctrl = rpc("POST", "/api/prepare-control", tok2, {
            "request_id": "rot-ctrl-2",
            "scope": boot2["scope"],
            "control": "PAUSE_NEW_RISK",
            "expected_generation": boot2["fence_generation"],
        })
        self.assertEqual(st_fresh_prep, 200)
        st_fresh_req, fresh_out = rpc("POST", "/api/request-control", tok2, fresh_ctrl)
        self.assertEqual(st_fresh_req, 200)
        self.assertEqual(fresh_out["status"], "ACCEPTED")


if __name__ == "__main__":
    unittest.main()
