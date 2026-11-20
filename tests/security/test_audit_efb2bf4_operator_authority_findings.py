"""PR #25 security audit regression suite for operator, trader & authority findings [5], [8], [10], [11], [12].

Covers frozen-commit audit efb2bf47a5a86318dce4c33128d4f6f57c832666:
- [5]  Immutable constitutional 1.00% stop-risk & 10.00% drawdown ceilings + 3-Gear Adaptive Risk (trader side)
- [8]  Per-attempt worst-case DurableModelExecutionGate reservations, retries/fallbacks, settlement & auxiliary routes
- [10] Hardened local Ollama fallback provenance (SupervisedOllamaBinding, artifact digests, foreign listener, independent receipts)
- [11] Per-principal expiring CheckpointService replay windows, rate limits, & durable ADVANCE replay protection
- [12] AutonomousAiTrader.emergency_close_all() OANDA parity & drawdown-immune CLOSE/REDUCE
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest

from cas_forex_revamp.composition.autonomous_trader import (
    ACTIVE_GEAR_CONSERVATIVE,
    ACTIVE_GEAR_GROWTH,
    ACTIVE_GEAR_STRONG_TREND_RUNNER,
    AutonomousAiTrader,
    MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
    MAX_CONSTITUTIONAL_STOP_RISK_PCT,
    RISK_GEAR_AGGRESSIVE,
    RISK_GEAR_AUTO_ADAPTIVE,
    RISK_GEAR_CONSERVATIVE,
    resolve_adaptive_risk_and_quota,
)
from cas_forex_revamp.composition.trend_regime import (
    REGIME_CHOP_RANGE,
    REGIME_STRONG_TREND,
    REGIME_TREND_IGNITION,
)
from cas_forex_revamp.contracts import (
    ActionIntent,
    ActionKind,
    ActionOption,
    ContractError,
    DecisionFact,
    DecisionOrigin,
    DecisionRequest,
    EvidenceKind,
    EvidenceReference,
    InferenceBudget,
    RunScope,
    Side,
    StateReference,
    canonical_bytes,
    content_digest,
)
from cas_forex_revamp.operator.decisions import OperatorUnavailable
from cas_forex_revamp.operator.frontier_backends import (
    ENV_ANTHROPIC_API_KEY,
    ENV_GEMINI_API_KEY,
    ENV_OLLAMA_FALLBACK_ENABLED,
    FrontierConfigurationError,
    FrontierModelRegistry,
    FrontierReceiptVerifier,
    FrontierTransportError,
    OLLAMA_LOOPBACK_ENDPOINT,
    OLLAMA_SUPERVISOR_AUTH_HEADER,
    RetryPolicy,
    SupervisedOllamaBinding,
    SupervisedOllamaReceiptSigner,
    default_ollama_loopback_post,
    reject_preexisting_ollama_listener,
)
from cas_forex_revamp.operator.model import (
    ActualModelDecisionAdapter,
    DurableModelExecutionGate,
    InferenceReply,
    ModelInvocation,
    SYSTEM_POLICY,
    estimate_worst_case_cost_usd,
)
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    ValveRefusalError,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.dual_shield_router import (
    BarbellCapitalPolicy,
    BarbellPolicyRefusalError,
    DualShieldBrokerRouter,
    OandaQuoteTruthOracle,
)
from cas_forex_revamp.venue.external_paper_broker import (
    ENV_EXECUTION_MODE,
    ENV_OANDA_PRACTICE_ACCOUNT_ID,
    ENV_OANDA_PRACTICE_TOKEN,
    EXECUTION_MODE_DEMO,
    OandaMutationJournal,
    OandaPracticePaperClient,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BROKER_OANDA_PRACTICE,
    Mt5Credentials,
    Mt5NativePythonTransport,
    Mt5PaperBrokerVenue,
    OandaPracticeFallbackVenue,
    OrderIntent,
    _RedactedSecret,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
for extra_path in (
    REPO_ROOT / "shared-interface",
    REPO_ROOT / "operational" / "authority" / "source",
    REPO_ROOT / "operational" / "authority" / "tests",
):
    extra_str = str(extra_path)
    if extra_str not in sys.path:
        sys.path.insert(0, extra_str)

from cas_forex_operational_contracts import checkpoint as ck  # noqa: E402
from cas_forex_operational_contracts.common import canonical_bytes as op_canonical_bytes, digest as op_digest  # noqa: E402
from cas_forex_authority.authentication import AuthorityError  # noqa: E402
from cas_forex_authority.checkpoint_service import CheckpointService  # noqa: E402

T0 = datetime(2026, 11, 20, 16, 0, 0, tzinfo=timezone.utc)
SYNTH_API_KEY = "test-placeholder-key-01"
SYNTH_SUP_SECRET = "sup-launch-secret-" + ("a" * 32)


def _make_decision_request(request_id: str = "req-sec-1", action_ref: str = "opt-0") -> DecisionRequest:
    scope = RunScope("acct-sec", "run-sec", 1, "b1", "p1", "s1", "sec-test")
    st = StateReference("st-sec-1", scope, 1, T0, T0 + timedelta(seconds=60), 1)
    intent = ActionIntent(
        intent_id=f"ord-{request_id}",
        scope=scope,
        decision_id=f"dec-{request_id}",
        opportunity_id=f"opp-{request_id}",
        action_ref=action_ref,
        kind=ActionKind.OPEN,
        origin=DecisionOrigin.ACTUAL_MODEL,
        instrument_id="EURUSD",
        source_state=st,
        created_at=T0,
        expires_at=T0 + timedelta(seconds=60),
        quantity=Decimal("10000"),
        side=Side.BUY,
        limit_price=Decimal("1.10050"),
        stop_price=Decimal("1.09850"),
        take_profit_price=Decimal("1.10450"),
    )
    ev_id = "ev-sec-1"
    fact_obj = {"symbol": "EURUSD", "bid": "1.10000", "ask": "1.10010"}
    return DecisionRequest(
        request_id=request_id,
        opportunity_set_id="set-sec-1",
        state=st,
        options=(ActionOption(action_ref, "trend", "M1", "BUY EURUSD", intent),),
        facts=(DecisionFact("f-1", "quote", canonical_bytes(fact_obj).decode("utf-8"), (ev_id,)),),
        evidence=(EvidenceReference(ev_id, EvidenceKind.OBSERVATION, "test", content_digest(fact_obj), T0),),
    )


def _selection_json(req: DecisionRequest, selected_action_ref: str | None = "opt-0") -> str:
    tag = "wait_none" if selected_action_ref is None else selected_action_ref
    return json.dumps({
        "request_id": req.request_id,
        "opportunity_set_id": req.opportunity_set_id,
        "source_state_id": req.state.state_id,
        "selected_action_ref": selected_action_ref,
        "reason": f"ID=0{tag} verified",
        "evidence_ids": [req.evidence[0].evidence_id],
    })


def _make_supervised_ollama_bundle(
    root: Path,
    *,
    algorithm: str = "Ed25519",
    port: int = 22434,
    listener_ok: bool = True,
) -> tuple[SupervisedOllamaBinding, SupervisedOllamaReceiptSigner, dict[str, Path]]:
    paths: dict[str, Path] = {}
    digests: dict[str, str] = {}
    for name, payload in (
        ("executable", b"supervised-ollama-binary-v0.40.2"),
        ("manifest", b'{"model":"qwen3:0.6b","tag":"pinned-v1"}'),
        ("weights", b"gguf-weights-payload-verified-0001"),
        ("template", b"{{ .System }}\n{{ .Prompt }}"),
        ("tokenizer", b'{"vocab_size":151936}'),
    ):
        fp = root / f"{name}.bin"
        fp.write_bytes(payload)
        paths[name] = fp
        digests[name] = sha256(payload).hexdigest()

    signer = SupervisedOllamaReceiptSigner(
        algorithm=algorithm,
        signing_key=bytes(range(20, 52)),
        pid=os.getpid(),
        start_time="sec-test-start-1",
    )
    binding = SupervisedOllamaBinding(
        pid=os.getpid(),
        start_time="sec-test-start-1",
        executable_sha256=digests["executable"],
        model_manifest_sha256=digests["manifest"],
        weights_sha256=digests["weights"],
        template_sha256=digests["template"],
        tokenizer_sha256=digests["tokenizer"],
        endpoint_url=f"http://127.0.0.1:{port}/api/chat",
        auth_secret=SYNTH_SUP_SECRET,
        receipt_verify_key=signer.public_verify_key(),
        receipt_algorithm=algorithm,
        executable_path=paths["executable"],
        manifest_path=paths["manifest"],
        weights_path=paths["weights"],
        template_path=paths["template"],
        tokenizer_path=paths["tokenizer"],
        process_verifier=lambda _b: True,
        listener_ownership_verifier=lambda _b: listener_ok,
    )
    return binding, signer, paths


class _FakeMt5SdkForClose:
    def __init__(self, login: int, server: str, *, balance: Decimal, equity: Decimal, positions: list[SimpleNamespace]) -> None:
        self._login = login
        self._server = server
        self._balance = balance
        self._equity = equity
        self.positions = list(positions)
        self.closed_orders: list[dict[str, object]] = []
        self.ACCOUNT_TRADE_MODE_DEMO = 0
        self.ACCOUNT_TRADE_MODE_REAL = 2
        self.TRADE_ACTION_DEAL = 1
        self.TRADE_ACTION_SLTP = 6
        self.ORDER_TYPE_BUY = 0
        self.ORDER_TYPE_SELL = 1
        self.ORDER_TIME_GTC = 0
        self.ORDER_FILLING_IOC = 1
        self.TRADE_RETCODE_DONE = 10009
        self._seq = 5000

    def initialize(self, **_kwargs) -> bool:
        return True

    def login(self, *_args, **_kwargs) -> bool:
        return True

    def symbol_info(self, _sym: str) -> SimpleNamespace:
        return SimpleNamespace(
            volume_min=Decimal("0.01"),
            volume_max=Decimal("100.00"),
            volume_step=Decimal("0.01"),
            trade_contract_size=Decimal("100000"),
            digits=5,
            point=Decimal("0.00001"),
        )

    def shutdown(self) -> None:
        return None

    def last_error(self) -> tuple[int, str]:
        return (0, "OK")

    def account_info(self) -> SimpleNamespace:
        return SimpleNamespace(
            login=self._login,
            server=self._server,
            trade_mode=0,
            currency="USD",
            leverage=500,
            balance=self._balance,
            equity=self._equity,
            margin=Decimal("200"),
            margin_free=self._equity - Decimal("200"),
            margin_level=Decimal("5000"),
            profit=self._equity - self._balance,
        )

    def positions_get(self):
        return tuple(self.positions)

    def symbol_select(self, _sym: str, _enable: bool) -> bool:
        return True

    def symbol_info_tick(self, _sym: str) -> SimpleNamespace:
        return SimpleNamespace(bid=Decimal("1.09500"), ask=Decimal("1.09510"), time_msc=1763654400000)

    def order_send(self, req: dict[str, object]) -> SimpleNamespace:
        self._seq += 1
        self.closed_orders.append(dict(req))
        target_ticket = req.get("position")
        self.positions = [p for p in self.positions if p.ticket != target_ticket]
        return SimpleNamespace(
            retcode=10009,
            order=self._seq,
            deal=self._seq + 10,
            price=Decimal("1.09505"),
            volume=req.get("volume", Decimal("0.10")),
            comment="closed",
        )


class _FakeOandaRestTransport:
    """In-memory OANDA v20 practice REST simulator for Finding [12] tests."""

    def __init__(self, *, nav: Decimal, trades: list[dict[str, object]]) -> None:
        self.nav = nav
        self.margin_available = nav - Decimal("500.00")
        self.trades: dict[str, dict[str, object]] = {str(t["id"]): dict(t) for t in trades}
        self.close_calls: list[tuple[str, str, dict[str, object]]] = []
        self._tx = 9000

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None, _timeout: float, _max_wire_bytes: int) -> bytes:
        if method == "GET" and url.endswith("/summary"):
            payload = {
                "account": {
                    "id": "101-001-9988776-001",
                    "currency": "USD",
                    "NAV": str(self.nav),
                    "balance": str(self.nav),
                    "marginAvailable": str(self.margin_available),
                    "marginUsed": "500.00",
                    "openTradeCount": len(self.trades),
                }
            }
            return json.dumps(payload).encode("utf-8")
        if method == "GET" and url.endswith("/openTrades"):
            return json.dumps({"trades": list(self.trades.values())}).encode("utf-8")
        if method == "GET" and "/pricing" in url:
            prices = [
                {
                    "instrument": "GBP_USD",
                    "time": "2026-11-20T16:00:00Z",
                    "bids": [{"price": "1.26500", "liquidity": 1000000}],
                    "asks": [{"price": "1.26520", "liquidity": 1000000}],
                    "tradeable": True,
                },
                {
                    "instrument": "EUR_USD",
                    "time": "2026-11-20T16:00:00Z",
                    "bids": [{"price": "1.09500", "liquidity": 1000000}],
                    "asks": [{"price": "1.09510", "liquidity": 1000000}],
                    "tradeable": True,
                },
            ]
            return json.dumps({"prices": prices}).encode("utf-8")
        if method == "PUT" and "/trades/" in url and url.endswith("/close"):
            parts = url.split("/trades/", 1)[1]
            trade_id = parts.split("/close", 1)[0]
            req_doc = json.loads((body or b"{}").decode("utf-8"))
            self.close_calls.append((method, url, req_doc))
            tr = self.trades.get(trade_id)
            if tr is None:
                raise RuntimeError("TRADE_DOESNT_EXIST")
            req_units = str(req_doc.get("units", "ALL"))
            cur_signed = Decimal(str(tr["currentUnits"]))
            abs_cur = abs(cur_signed)
            if req_units == "ALL" or Decimal(req_units) >= abs_cur:
                closed_units = abs_cur
                del self.trades[trade_id]
            else:
                closed_units = Decimal(req_units)
                rem = abs_cur - closed_units
                tr["currentUnits"] = str(rem if cur_signed > 0 else -rem)
            self._tx += 1
            resp = {
                "orderCreateTransaction": {"id": str(self._tx)},
                "orderFillTransaction": {
                    "id": str(self._tx + 1),
                    "instrument": tr["instrument"],
                    "units": str(-closed_units if cur_signed > 0 else closed_units),
                    "price": "1.26510",
                    "pl": "-45.50",
                    "tradeClosed": {"tradeID": trade_id, "units": str(closed_units), "realizedPL": "-45.50"},
                },
            }
            return json.dumps(resp).encode("utf-8")
        raise RuntimeError("not found")


class _PortableSqliteDatabase:
    """Cross-platform durable SQLite seam matching DurableDatabase.transaction() for Finding [11] tests."""

    def __init__(self, db_path: Path) -> None:
        self.path = db_path

    @contextmanager
    def transaction(self, *, write: bool = True, final_guard=None):
        conn = sqlite3.connect(str(self.path), isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield conn
            if final_guard is not None:
                final_guard()
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()


class _PortableCheckpointStore:
    """Minimal portable CheckpointStore double backed by a real SQLite DB for cross-platform Finding [11] tests."""

    def __init__(self, db_path: Path, authority_id: str, clock_domain: dict, access_sha: str, status: dict) -> None:
        self.database = _PortableSqliteDatabase(db_path)
        self.authority_id = authority_id
        self.clock_domain = clock_domain
        self.access_sha = access_sha
        self.status = status
        self.advances: list[str] = []

    def _resp(self, request: dict, *, outcome: str, now: dict) -> dict:
        req_sha = op_digest(op_canonical_bytes(request))
        gen = len(self.advances)
        if outcome == "COMMITTED":
            cp_utf8 = "{}"
            cp_sha = op_digest(cp_utf8.encode("utf-8"))
            att_utf8 = "{}"
            hist = [
                {
                    "generation": idx + 1,
                    "request_sha256": req_sha,
                    "checkpoint_sha256": cp_sha,
                    "checkpoint_utf8": cp_utf8,
                    "checkpoint_attestation_utf8": att_utf8,
                }
                for idx in range(gen)
            ]
            head_sha = cp_sha
        else:
            cp_utf8 = None
            att_utf8 = None
            hist = []
            head_sha = "0" * 64
        return ck.validate(
            "CheckpointRpcResponse",
            {
                "format": "forex.checkpoint-rpc-response/2",
                "request_sha256": req_sha,
                "nonce_hex": request["nonce_hex"],
                "binding": request["binding"],
                "original_setup_key": request["original_setup_key"],
                "checkpoint_authority_id": self.authority_id,
                "store_instance_id": "portable-store-1",
                "status": outcome,
                "observed": now,
                "clock_domain": self.clock_domain,
                "authority_view_sha256": op_digest(op_canonical_bytes(self.status)),
                "generation": gen,
                "head_sha256": head_sha,
                "checkpoint_utf8": cp_utf8,
                "checkpoint_attestation_utf8": att_utf8,
                "history": hist,
                "failure_code": None,
                "access_selection_sha256": self.access_sha,
            },
        ).payload()

    def read_current(self, request: dict, *, authenticated_caller: dict, now: dict) -> dict:
        return self._resp(request, outcome="ABSENT", now=now)

    def lookup_exact(self, request: dict, *, authenticated_caller: dict, now: dict) -> dict:
        return self._resp(request, outcome="EXACT_RECOVERY", now=now)

    def compare_and_append(self, request: dict, *, authenticated_caller: dict, now: dict) -> dict:
        self.advances.append(request["nonce_hex"])
        return self._resp(request, outcome="COMMITTED", now=now)


class AuditEfb2bf4OperatorAuthorityTests(unittest.TestCase):
    # =========================================================================
    # Finding [5]: Immutable 1.00% Stop-Risk & 10.00% Drawdown Constitutional Ceilings
    # =========================================================================

    def test_finding_5_reject_over_1pct_stop_risk_and_over_10pct_drawdown_in_gears_and_trader(self) -> None:
        self.assertEqual(MAX_CONSTITUTIONAL_STOP_RISK_PCT, Decimal("1.00"))
        self.assertEqual(MAX_CONSTITUTIONAL_DRAWDOWN_PCT, Decimal("0.10"))

        # Reject 1.01% stop-risk and 10.01% drawdown immediately
        with self.assertRaises(ContractError):
            resolve_adaptive_risk_and_quota(
                owner_gear_mode=RISK_GEAR_AUTO_ADAPTIVE,
                regime=REGIME_STRONG_TREND,
                drawdown_pct=Decimal("0"),
                consecutive_losses=0,
                owner_max_risk_pct=Decimal("1.01"),
                owner_max_drawdown_pct=Decimal("0.10"),
                owner_soft_quota_usd=Decimal("500"),
                owner_hard_quota_usd=Decimal("1000"),
            )
        with self.assertRaises(ContractError):
            resolve_adaptive_risk_and_quota(
                owner_gear_mode=RISK_GEAR_AUTO_ADAPTIVE,
                regime=REGIME_STRONG_TREND,
                drawdown_pct=Decimal("0"),
                consecutive_losses=0,
                owner_max_risk_pct=Decimal("1.00"),
                owner_max_drawdown_pct=Decimal("0.1001"),
                owner_soft_quota_usd=Decimal("500"),
                owner_hard_quota_usd=Decimal("1000"),
            )

        # Redefined 3-Gear Adaptive Risk: Conservative 0.50%, Auto 0.50% -> 0.75% -> 1.00%, Aggressive 1.00%
        base = dict(
            owner_max_risk_pct=Decimal("1.00"),
            owner_max_drawdown_pct=Decimal("0.10"),
            owner_soft_quota_usd=Decimal("2000"),
            owner_hard_quota_usd=Decimal("3000"),
        )
        g_cons = resolve_adaptive_risk_and_quota(
            owner_gear_mode=RISK_GEAR_CONSERVATIVE,
            regime=REGIME_STRONG_TREND,
            drawdown_pct=Decimal("0"),
            consecutive_losses=0,
            **base,
        )
        self.assertEqual(g_cons["active_gear"], ACTIVE_GEAR_CONSERVATIVE)
        self.assertEqual(g_cons["effective_risk_pct"], "0.5")

        g_auto_chop = resolve_adaptive_risk_and_quota(
            owner_gear_mode=RISK_GEAR_AUTO_ADAPTIVE,
            regime=REGIME_CHOP_RANGE,
            drawdown_pct=Decimal("0.01"),
            consecutive_losses=0,
            **base,
        )
        self.assertEqual(g_auto_chop["effective_risk_pct"], "0.5")

        g_auto_ign = resolve_adaptive_risk_and_quota(
            owner_gear_mode=RISK_GEAR_AUTO_ADAPTIVE,
            regime=REGIME_TREND_IGNITION,
            drawdown_pct=Decimal("0.01"),
            consecutive_losses=0,
            **base,
        )
        self.assertEqual(g_auto_ign["active_gear"], ACTIVE_GEAR_GROWTH)
        self.assertEqual(g_auto_ign["effective_risk_pct"], "0.75")

        g_auto_strong = resolve_adaptive_risk_and_quota(
            owner_gear_mode=RISK_GEAR_AUTO_ADAPTIVE,
            regime=REGIME_STRONG_TREND,
            drawdown_pct=Decimal("0.01"),
            consecutive_losses=0,
            **base,
        )
        self.assertEqual(g_auto_strong["active_gear"], ACTIVE_GEAR_STRONG_TREND_RUNNER)
        self.assertEqual(g_auto_strong["effective_risk_pct"], "1")

        g_aggr = resolve_adaptive_risk_and_quota(
            owner_gear_mode=RISK_GEAR_AGGRESSIVE,
            regime=REGIME_STRONG_TREND,
            drawdown_pct=Decimal("0"),
            consecutive_losses=0,
            **base,
        )
        self.assertEqual(g_aggr["effective_risk_pct"], "1")
        self.assertLessEqual(Decimal(g_aggr["effective_risk_pct"]), Decimal("1.00"))

        # Tightening overrides (< 1.00% / < 0.10) remain permitted and strictly honored
        g_tight = resolve_adaptive_risk_and_quota(
            owner_gear_mode=RISK_GEAR_AGGRESSIVE,
            regime=REGIME_STRONG_TREND,
            drawdown_pct=Decimal("0"),
            consecutive_losses=0,
            owner_max_risk_pct=Decimal("0.40"),
            owner_max_drawdown_pct=Decimal("0.05"),
            owner_soft_quota_usd=Decimal("500"),
            owner_hard_quota_usd=Decimal("1000"),
        )
        self.assertEqual(g_tight["effective_risk_pct"], "0.4")
        self.assertEqual(g_tight["owner_max_drawdown_pct"], "0.05")

        # Trader cockpit gear switching & Valve view NEVER exceed 1.00% stop risk or 0.10 drawdown
        with tempfile.TemporaryDirectory() as td:
            gate = load_default_forex_valve_gate()
            oracle = OandaQuoteTruthOracle.from_static_quotes({"EURUSD": (Decimal("1.10000"), Decimal("1.10010"))})
            router = DualShieldBrokerRouter(
                environ={ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO},
                valve_gate=gate,
                oracle=oracle,
                equity_attestations={
                    BROKER_OANDA_PRACTICE: Decimal("80000"),
                    BROKER_HUGOSWAY_MT5: Decimal("12000"),
                    BROKER_LHFX_MT5: Decimal("8000"),
                },
                clock=lambda: T0,
            )
            trader = AutonomousAiTrader(
                router=router,
                model_registry=FrontierModelRegistry(environ={}),
                valve_gate=gate,
                execution_gate=DurableModelExecutionGate(Path(td) / "gate.sqlite3", clock=lambda: T0),
                clock=lambda: T0,
            )
            snap = trader.set_risk_gear_mode(RISK_GEAR_AGGRESSIVE, now=T0)
            self.assertLessEqual(Decimal(snap["risk_gear"]["effective_risk_pct"]), Decimal("1.00"))
            self.assertLessEqual(Decimal(snap["risk_gear"]["owner_max_drawdown_pct"]), Decimal("0.10"))

            view = trader._build_valve_view(
                total_eq=Decimal("90000"),
                peak_eq=Decimal("100000"),
                new_risk_permission="ALLOWED",
                management_permission="ALLOWED",
            )
            self.assertEqual(view["policy"]["max_drawdown_pct"], "0.1")

            # At 10.00% drawdown, BOTH router barbell and Valve VETO new risk
            with self.assertRaises(BarbellPolicyRefusalError):
                router.barbell.require_drawdown(current_equity=Decimal("90000"), peak_equity=Decimal("100000"))

            req = _make_decision_request()
            with self.assertRaises(ValveRefusalError):
                trader._make_valve_request_and_clear(
                    intent=req.options[0].intent,
                    strategy_id="test",
                    timeframe="M1",
                    label="BUY EURUSD",
                    reason="test 10% dd veto",
                    bid=Decimal("1.10000"),
                    ask=Decimal("1.10010"),
                    total_eq=Decimal("90000"),
                    peak_eq=Decimal("100000"),
                    now=T0,
                )

    # =========================================================================
    # Finding [8]: Per-Attempt Worst-Case Durable Model Spend Gate & Auxiliary Routes
    # =========================================================================

    def test_finding_8_max_token_budget_worst_case_reservation_precedes_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "model_gate.sqlite3"
            # Worst-case cost for claude-5.5 with 12,288 output tokens exceeds $0.92 (> $0.50 cap)
            wc = estimate_worst_case_cost_usd("claude-5.5", 4000, 12288)
            self.assertGreater(wc, Decimal("0.92"))
            # Unknown cloud model defaults to conservative flagship pricing
            wc_unknown = estimate_worst_case_cost_usd("unlisted-cloud-v9", 4000, 12288)
            self.assertEqual(wc_unknown, wc)

            gate = DurableModelExecutionGate(
                db,
                max_calls_per_day=100,
                max_daily_spend_usd=Decimal("0.50"),
                clock=lambda: T0,
            )
            http_calls = [0]

            def should_never_run(*_args, **_kwargs):
                http_calls[0] += 1
                return 200, b"{}"

            reg = FrontierModelRegistry(
                environ={ENV_ANTHROPIC_API_KEY: SYNTH_API_KEY},
                clock=lambda: T0,
                http_post=should_never_run,
                resolve_dns=lambda _h: None,
                execution_gate=gate,
            )
            spec, backend, verifier = reg.build_backend("claude-5.5", reasoning_effort="high", execution_gate=gate)
            req = _make_decision_request("req-12288")
            adapter = ActualModelDecisionAdapter(
                adapter_id="test-12288",
                model=spec,
                budget=InferenceBudget(
                    max_calls=1,
                    max_input_tokens_per_call=16_384,
                    max_generated_tokens_per_call=12_288,
                    max_seconds_per_call=25,
                    max_total_seconds=25,
                ),
                backend=backend,
                receipt_verifier=verifier,
                execution_gate=gate,
                clock=lambda: T0,
            )
            with self.assertRaises(OperatorUnavailable) as ctx:
                adapter.decide(req)
            self.assertIn("MODEL_DAILY_SPEND_CAP_EXCEEDED", str(ctx.exception))
            self.assertEqual(http_calls[0], 0)

    def test_finding_8_two_failures_plus_success_creates_three_durable_reservations(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "retry_gate.sqlite3"
            gate = DurableModelExecutionGate(
                db,
                max_calls_per_day=50,
                max_daily_spend_usd=Decimal("10.00"),
                clock=lambda: T0,
            )
            req = _make_decision_request("req-retry-3")
            sel_text = _selection_json(req, "opt-0")
            calls = [0]

            def flaky_then_ok(_url, _hdrs, _body, _timeout, _max_bytes):
                calls[0] += 1
                if calls[0] <= 2:
                    return 503, b'{"error":{"message":"overloaded"}}'
                return 200, json.dumps({
                    "content": [{"type": "text", "text": sel_text}],
                    "usage": {"input_tokens": 120, "output_tokens": 45},
                }).encode("utf-8")

            reg = FrontierModelRegistry(
                environ={ENV_ANTHROPIC_API_KEY: SYNTH_API_KEY},
                clock=lambda: T0,
                sleep=lambda _s: None,
                http_post=flaky_then_ok,
                resolve_dns=lambda _h: None,
                retry_policy=RetryPolicy(max_attempts=3, base_delay_seconds=Decimal("0"), max_delay_seconds=Decimal("0")),
                execution_gate=gate,
            )
            spec, backend, verifier = reg.build_backend("claude-fable-5.2", reasoning_effort="low", execution_gate=gate)
            adapter = ActualModelDecisionAdapter(
                adapter_id="test-retries",
                model=spec,
                budget=InferenceBudget(
                    max_calls=1,
                    max_input_tokens_per_call=16_384,
                    max_generated_tokens_per_call=2048,
                    max_seconds_per_call=25,
                    max_total_seconds=25,
                ),
                backend=backend,
                receipt_verifier=verifier,
                execution_gate=gate,
                clock=lambda: T0,
            )
            result = adapter.decide(req)
            self.assertEqual(result.selection.selected_action_ref, "opt-0")
            self.assertEqual(calls[0], 3)

            # Reopen fresh gate on same SQLite DB to verify durability
            reopened = DurableModelExecutionGate(db, max_calls_per_day=50, max_daily_spend_usd=Decimal("10.00"), clock=lambda: T0)
            rows = reopened.list_reservations()
            self.assertEqual(len(rows), 3)
            self.assertEqual([r["attempt_number"] for r in rows], [1, 2, 3])
            # Failed attempts 1 & 2 retain full worst-case reservation
            for failed_row in rows[:2]:
                self.assertEqual(failed_row["outcome"], "TRANSPORT_ERROR")
                self.assertIsNone(failed_row["actual_cost_usd"])
                self.assertEqual(failed_row["settled_cost_usd"], failed_row["reserved_cost_usd"])
                self.assertGreater(Decimal(failed_row["settled_cost_usd"]), Decimal("0.03"))
            # Successful attempt 3 refunds unused reservation down to confirmed actual usage
            ok_row = rows[2]
            self.assertEqual(ok_row["outcome"], "CONFIRMED_USAGE")
            self.assertIsNotNone(ok_row["actual_cost_usd"])
            self.assertLess(Decimal(ok_row["settled_cost_usd"]), Decimal(ok_row["reserved_cost_usd"]))
            snap = reopened.snapshot(now=T0)
            self.assertEqual(snap["calls_count"], 3)

    def test_finding_8_unknown_and_timeout_outcomes_retain_worst_case_and_prevent_double_settle(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "unknown_gate.sqlite3"
            gate = DurableModelExecutionGate(db, max_calls_per_day=20, max_daily_spend_usd=Decimal("5.00"), clock=lambda: T0)
            r1 = gate.reserve_attempt(
                model_id="claude-5.5",
                request_id="req-timeout-1",
                route_kind="decision",
                attempt_number=1,
                input_chars_or_tokens=2000,
                max_output_tokens=4096,
                now=T0,
            )
            settled = gate.settle_attempt(r1["reservation_id"], outcome="TIMEOUT", now=T0)
            self.assertEqual(settled["refunded_usd"], "0.000000")
            self.assertEqual(settled["settled_cost_usd"], r1["reserved_cost_usd"])
            # Double-settlement is strictly rejected
            with self.assertRaises(ContractError):
                gate.settle_attempt(r1["reservation_id"], actual_cost_usd=Decimal("0.000100"), outcome="CONFIRMED_USAGE", now=T0)

            # Provider HTTP 200 omitting usage metadata retains full worst-case reservation
            req = _make_decision_request("req-no-usage")
            sel_text = _selection_json(req, "opt-0")

            def no_usage_http(_url, _hdrs, _body, _timeout, _max_bytes):
                return 200, json.dumps({"content": [{"type": "text", "text": sel_text}]}).encode("utf-8")

            reg = FrontierModelRegistry(
                environ={ENV_ANTHROPIC_API_KEY: SYNTH_API_KEY},
                clock=lambda: T0,
                http_post=no_usage_http,
                resolve_dns=lambda _h: None,
                execution_gate=gate,
            )
            spec, backend, verifier = reg.build_backend("claude-fable-5.2", reasoning_effort="low", execution_gate=gate)
            ActualModelDecisionAdapter(
                adapter_id="test-no-usage",
                model=spec,
                budget=InferenceBudget(
                    max_calls=1,
                    max_input_tokens_per_call=16_384,
                    max_generated_tokens_per_call=2048,
                    max_seconds_per_call=25,
                    max_total_seconds=25,
                ),
                backend=backend,
                receipt_verifier=verifier,
                execution_gate=gate,
                clock=lambda: T0,
            ).decide(req)
            rows = gate.list_reservations()
            self.assertEqual(rows[-1]["outcome"], "UNKNOWN")
            self.assertEqual(rows[-1]["settled_cost_usd"], rows[-1]["reserved_cost_usd"])

    def test_finding_8_explainer_transcription_tts_and_scout_enforce_same_durable_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "aux_gate.sqlite3"
            gate = DurableModelExecutionGate(
                db,
                max_calls_per_day=100,
                max_daily_spend_usd=Decimal("0.09"),
                clock=lambda: T0,
            )
            http_calls = [0]

            def gemini_aux_http(url, _hdrs, _body, _timeout, _max_bytes):
                http_calls[0] += 1
                if ":decide" in url:
                    return 404, b'{"error":{"code":404}}'
                if "tts" in url:
                    return 200, json.dumps({
                        "candidates": [{
                            "content": {"parts": [{"inlineData": {"mimeType": "audio/L16;codec=pcm;rate=24000", "data": "AAAA"}}]}
                        }],
                        "usageMetadata": {"promptTokenCount": 20, "candidatesTokenCount": 200},
                    }).encode("utf-8")
                if "gemini-2.5-flash" in url:
                    return 200, json.dumps({
                        "candidates": [{"content": {"parts": [{"text": json.dumps({"decisions": [{"market": "EURUSD", "choice": "WAIT", "probability": "0.40"}]})}]}}],
                        "usageMetadata": {"promptTokenCount": 50, "candidatesTokenCount": 30},
                    }).encode("utf-8")
                return 200, json.dumps({
                    "candidates": [{"content": {"parts": [{"text": json.dumps({"spoken_question": "Status?", "answer": "All systems nominal."})}]}}],
                    "usageMetadata": {"promptTokenCount": 120, "candidatesTokenCount": 40},
                }).encode("utf-8")

            reg = FrontierModelRegistry(
                environ={ENV_GEMINI_API_KEY: SYNTH_API_KEY},
                clock=lambda: T0,
                sleep=lambda _s: None,
                http_post=gemini_aux_http,
                resolve_dns=lambda _h: None,
                retry_policy=RetryPolicy(max_attempts=1),
                execution_gate=gate,
            )

            # 1. Text explainer call (route_kind="explainer")
            ans = reg.answer_explainer_question("Explain status", context_summary={"execution_mode": "DEMO"})
            self.assertEqual(ans["source"], "FRONTIER_READ_ONLY")

            # 2. Voice transcription explainer call (route_kind="transcription")
            import base64
            audio_b64 = base64.b64encode(b"RIFF" + (bytes([0]) * 512)).decode("ascii")
            ans_audio = reg.answer_explainer_question(
                "",
                context_summary={"execution_mode": "DEMO"},
                audio_base64=audio_b64,
                audio_mime_type="audio/wav",
            )
            self.assertEqual(ans_audio["source"], "FRONTIER_READ_ONLY")

            # 3. TTS call (route_kind="tts")
            tts = reg.synthesize_explainer_speech("All systems nominal.", voice_name="Kore")
            self.assertTrue(tts["ok"])

            # 4. Scout call (:decide 404 -> gemini-2.5-flash fallback = 2 durable reservations!)
            scout = reg.scout_opportunities([{"market": "EURUSD", "choices": ["WAIT", "opt-0"]}])
            self.assertTrue(scout["executed"])

            rows = gate.list_reservations()
            route_kinds = [r["route_kind"] for r in rows]
            self.assertIn("explainer", route_kinds)
            self.assertIn("transcription", route_kinds)
            self.assertIn("tts", route_kinds)
            self.assertEqual(route_kinds.count("scout"), 2)

            # 5. Exhaust ceiling via a tiny spend gate and prove Explainer, Transcription & TTS all fail closed
            tight_gate = DurableModelExecutionGate(
                Path(td) / "tight.sqlite3",
                max_calls_per_day=100,
                max_daily_spend_usd=Decimal("0.0050"),
                clock=lambda: T0,
            )
            before_calls = http_calls[0]
            with self.assertRaises(OperatorUnavailable):
                reg.answer_explainer_question("Blocked?", execution_gate=tight_gate)
            with self.assertRaises(OperatorUnavailable):
                reg.answer_explainer_question("", audio_base64=audio_b64, audio_mime_type="audio/wav", execution_gate=tight_gate)
            with self.assertRaises(OperatorUnavailable):
                reg.synthesize_explainer_speech("Blocked TTS speech", execution_gate=tight_gate)
            self.assertEqual(http_calls[0], before_calls)

            # Direct authorize_auxiliary_call rejects invalid route_kind
            with self.assertRaises(ContractError):
                tight_gate.authorize_auxiliary_call(route_kind="invalid", model_id="gemini-4-neon", max_output_tokens=100)

    # =========================================================================
    # Finding [10]: Hardened Local Ollama Fallback Provenance
    # =========================================================================

    def test_finding_10_refuses_unsupervised_and_preexisting_foreign_listener(self) -> None:
        # 1. Config flag + ollama_http_post ALONE never enables fallback without SupervisedOllamaBinding
        reg = FrontierModelRegistry(
            environ={ENV_OLLAMA_FALLBACK_ENABLED: "1"},
            clock=lambda: T0,
            ollama_http_post=lambda *_a: (200, b"{}"),
        )
        self.assertFalse(reg.is_model_ready("qwen3:0.6b"))
        self.assertFalse(reg.catalog_snapshot()["offline_fallback_enabled"])

        spec, backend, _ = reg.build_backend("qwen3:0.6b")
        req = _make_decision_request("req-unsup")
        inv = ModelInvocation(
            content_digest(req),
            spec,
            "session-" + content_digest(("unsup", req.request_id)),
            SYSTEM_POLICY,
            canonical_bytes(req).decode("utf-8"),
            InferenceBudget(1, 16_384, 256, 10, 10),
        )
        with self.assertRaises(FrontierConfigurationError) as ctx:
            backend.infer(inv)
        self.assertIn("OLLAMA_UNSUPERVISED_ENDPOINT_FORBIDDEN", str(ctx.exception))

        # 2. Direct default_ollama_loopback_post without SupervisedOllamaBinding fails closed
        with self.assertRaises(FrontierConfigurationError):
            default_ollama_loopback_post(OLLAMA_LOOPBACK_ENDPOINT, {}, b"{}", 2.0, 4096)

        # 3. Binding to shared default port 11434 is forbidden outright
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(FrontierConfigurationError) as ctx_port:
                _make_supervised_ollama_bundle(Path(td), port=11434)
            self.assertIn("OLLAMA_SHARED_DEFAULT_PORT_FORBIDDEN", str(ctx_port.exception))

        # 4. Real pre-existing foreign listener on loopback port is detected & rejected
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as foreign_srv:
            foreign_srv.bind(("127.0.0.1", 0))
            foreign_srv.listen(1)
            foreign_port = int(foreign_srv.getsockname()[1])
            with self.assertRaises(FrontierConfigurationError) as ctx_fl:
                reject_preexisting_ollama_listener("127.0.0.1", foreign_port)
            self.assertIn("OLLAMA_PREEXISTING_FOREIGN_LISTENER", str(ctx_fl.exception))

            with tempfile.TemporaryDirectory() as td:
                binding_foreign, _, _ = _make_supervised_ollama_bundle(Path(td), port=foreign_port, listener_ok=False)
                reg_f = FrontierModelRegistry(
                    environ={ENV_OLLAMA_FALLBACK_ENABLED: "1"},
                    clock=lambda: T0,
                    ollama_http_post=lambda *_a: (200, b"{}"),
                    supervised_ollama=binding_foreign,
                )
                self.assertFalse(reg_f.is_model_ready("qwen3:0.6b"))
                spec_f, backend_f, _ = reg_f.build_backend("qwen3:0.6b")
                inv_f = ModelInvocation(
                    content_digest(req),
                    spec_f,
                    "session-" + content_digest(("foreign", req.request_id)),
                    SYSTEM_POLICY,
                    canonical_bytes(req).decode("utf-8"),
                    InferenceBudget(1, 16_384, 256, 10, 10),
                )
                with self.assertRaises(FrontierTransportError) as ctx_det:
                    backend_f.infer(inv_f)
                self.assertIn("OLLAMA_FOREIGN_LISTENER_DETECTED", str(ctx_det.exception))

    def test_finding_10_mutated_model_weights_or_manifest_fails_artifact_verification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binding, _, paths = _make_supervised_ollama_bundle(root, port=22435)
            http_calls = [0]

            def stub_post(*_a):
                http_calls[0] += 1
                return 200, b"{}"

            reg = FrontierModelRegistry(
                environ={ENV_OLLAMA_FALLBACK_ENABLED: "1"},
                clock=lambda: T0,
                ollama_http_post=stub_post,
                supervised_ollama=binding,
            )
            self.assertTrue(reg.is_model_ready("qwen3:0.6b"))

            # Mutate weights file on disk -> readiness flips False and infer fails BEFORE HTTP dispatch
            paths["weights"].write_bytes(b"TAMPERED-WEIGHTS-PAYLOAD")
            self.assertFalse(reg.is_model_ready("qwen3:0.6b"))
            spec, backend, _ = reg.build_backend("qwen3:0.6b")
            req = _make_decision_request("req-mut-w")
            inv = ModelInvocation(
                content_digest(req),
                spec,
                "session-" + content_digest(("mut-w", req.request_id)),
                SYSTEM_POLICY,
                canonical_bytes(req).decode("utf-8"),
                InferenceBudget(1, 16_384, 256, 10, 10),
            )
            with self.assertRaises(FrontierTransportError) as ctx_w:
                backend.infer(inv)
            self.assertIn("OLLAMA_ARTIFACT_HASH_MISMATCH", str(ctx_w.exception))
            self.assertEqual(http_calls[0], 0)

            # Restore weights and mutate manifest/tag -> also rejected
            paths["weights"].write_bytes(b"gguf-weights-payload-verified-0001")
            self.assertTrue(reg.is_model_ready("qwen3:0.6b"))
            paths["manifest"].write_bytes(b'{"model":"qwen3:0.6b","tag":"evil-tag"}')
            with self.assertRaises(FrontierTransportError) as ctx_m:
                backend.infer(inv)
            self.assertIn("OLLAMA_ARTIFACT_HASH_MISMATCH", str(ctx_m.exception))
            self.assertEqual(http_calls[0], 0)

    def test_finding_10_independent_supervisor_receipt_cannot_be_self_created_by_backend(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for algo, port in (("Ed25519", 22436), ("HMAC-SHA256", 22437)):
                sub = root / algo
                sub.mkdir()
                binding, signer, _ = _make_supervised_ollama_bundle(sub, algorithm=algo, port=port)
                self.assertNotIn(SYNTH_SUP_SECRET, repr(binding))

                req = _make_decision_request(f"req-ol-{algo}")
                sel_text = _selection_json(req, "opt-0")
                seen_headers: list[dict[str, str]] = []
                mode_box = ["MISSING"]
                expected_inv_ref: list[tuple[str, str, str]] = []

                rogue_signer = SupervisedOllamaReceiptSigner(
                    algorithm=algo,
                    signing_key=bytes(range(99, 131)),
                    pid=os.getpid(),
                    start_time="sec-test-start-1",
                )

                def fake_supervised_http(url, headers, _body, _timeout, _max_bytes):
                    seen_headers.append(dict(headers))
                    body_out: dict[str, object] = {
                        "message": {"content": sel_text},
                        "prompt_eval_count": 200,
                        "eval_count": 30,
                    }
                    inv_sha, m_id, art_sha = expected_inv_ref[0]
                    if mode_box[0] == "ROGUE":
                        body_out["cas_supervisor_receipt"] = rogue_signer.sign_receipt(
                            receipt_id=f"rcpt-ollama-rogue-{algo}",
                            invocation_sha256=inv_sha,
                            model_id=m_id,
                            artifact_sha256=art_sha,
                            response_sha256=sha256(sel_text.encode("utf-8")).hexdigest(),
                        )
                    elif mode_box[0] == "VALID":
                        body_out["cas_supervisor_receipt"] = signer.sign_receipt(
                            receipt_id=f"rcpt-ollama-valid-{algo}",
                            invocation_sha256=inv_sha,
                            model_id=m_id,
                            artifact_sha256=art_sha,
                            response_sha256=sha256(sel_text.encode("utf-8")).hexdigest(),
                        )
                    return 200, json.dumps(body_out).encode("utf-8")

                reg = FrontierModelRegistry(
                    environ={ENV_OLLAMA_FALLBACK_ENABLED: "1"},
                    clock=lambda: T0,
                    ollama_http_post=fake_supervised_http,
                    supervised_ollama=binding,
                )
                spec, backend, verifier = reg.build_backend("qwen3:0.6b")
                budget = InferenceBudget(1, 16_384, 256, 10, 10)
                expected_inv = ModelInvocation(
                    content_digest(req),
                    spec,
                    "session-" + content_digest(("isolated", req.request_id, 0)),
                    SYSTEM_POLICY,
                    canonical_bytes(req).decode("utf-8"),
                    budget,
                )
                expected_inv_ref.append((content_digest(expected_inv), spec.model_id, spec.artifact_sha256))

                # 1. Self-recording an Ollama receipt via FrontierReceiptVerifier.record() is FORBIDDEN
                forged_reply = InferenceReply(
                    raw_selection_json=sel_text,
                    receipt_id=f"rcpt-ollama-self-{algo}",
                    invocation_sha256=content_digest(expected_inv),
                    model=spec,
                    started_at=T0,
                    completed_at=T0,
                    input_tokens=backend.count_input_tokens(expected_inv),
                    generated_tokens=30,
                )
                with self.assertRaises(ContractError) as ctx_self:
                    verifier.record(forged_reply, expected_inv)
                self.assertIn("OLLAMA_SELF_RECORDED_RECEIPT_FORBIDDEN", str(ctx_self.exception))
                self.assertFalse(verifier.verify(forged_reply, expected_inv))

                # 2. Missing supervisor receipt in Ollama response fails closed
                mode_box[0] = "MISSING"
                with self.assertRaises(FrontierTransportError) as ctx_miss:
                    backend.infer(expected_inv)
                self.assertIn("OLLAMA_SUPERVISOR_RECEIPT_MISSING", str(ctx_miss.exception))
                self.assertEqual(seen_headers[-1].get(OLLAMA_SUPERVISOR_AUTH_HEADER), SYNTH_SUP_SECRET)

                # 3. Receipt signed by rogue key fails cryptographic verification in ActualModelDecisionAdapter
                mode_box[0] = "ROGUE"
                with self.assertRaises(ContractError) as ctx_rogue:
                    ActualModelDecisionAdapter(
                        adapter_id=f"adp-rogue-{algo}",
                        model=spec,
                        budget=budget,
                        backend=backend,
                        receipt_verifier=verifier,
                        execution_gate=lambda _i: None,
                        clock=lambda: T0,
                    ).decide(req)
                self.assertIn("independent inference receipt verification failed", str(ctx_rogue.exception))

                # 4. Legitimate receipt signed by independent supervisor key passes end-to-end
                mode_box[0] = "VALID"
                out = ActualModelDecisionAdapter(
                    adapter_id=f"adp-valid-{algo}",
                    model=spec,
                    budget=budget,
                    backend=backend,
                    receipt_verifier=verifier,
                    execution_gate=lambda _i: None,
                    clock=lambda: T0,
                ).decide(req)
                self.assertEqual(out.selection.selected_action_ref, "opt-0")

    # =========================================================================
    # Finding [11]: Per-Principal Expiring Checkpoint Replay Windows & Durable ADVANCE Ledger
    # =========================================================================

    def _build_two_principal_checkpoint_service(
        self,
        db_path: Path,
        *,
        per_principal_read_capacity: int = 8,
        per_principal_rate_limit: int = 8,
    ):
        import support as auth_support

        f = auth_support.fixture()
        # Add a second appointed principal ("observer") with its own process & Ed25519 key
        from dataclasses import replace as _dc_replace

        observer_key = bytes([7]) * 32
        observer_proc = auth_support.process("SETUP_CONSUMER", 99, 1001)
        f.keys["observer"] = observer_key
        new_access = dict(f.auth.access)
        new_access["callers"] = list(new_access["callers"]) + [
            {
                "principal_id": "observer",
                "signer_public_sha256": op_digest(observer_key),
                "component_manifest_sha256": "7" * 64,
                "actual_process": observer_proc,
                "operations": ["READ_CURRENT", "LOOKUP_TRANSITION"],
                "uses": ["SETUP_PROTOCOL"],
            }
        ]
        new_access_raw = ck.validate("CheckpointAccessSelection", new_access).raw
        f.auth.selection = _dc_replace(
            f.auth.selection,
            principal_keys=tuple(f.keys.items()),
            access_raw=new_access_raw,
            access_sha256=op_digest(new_access_raw),
        )
        store = _PortableCheckpointStore(
            db_path=db_path,
            authority_id="checkpoint",
            clock_domain=f.budget["clock_domain"],
            access_sha=f.auth.selection.access_sha256,
            status=f.status,
        )
        peers = SimpleNamespace(observe=lambda selected: selected)
        own_proc = auth_support.process("CHECKPOINT_CUSTODIAN", os.getpid(), 1002)
        svc = CheckpointService(
            authentication=f.auth,
            store=store,
            signer=f.checkpoint_signer,
            peers=peers,
            own_process=own_proc,
            per_principal_read_capacity=per_principal_read_capacity,
            per_principal_rate_limit=per_principal_rate_limit,
        )
        return auth_support, f, store, svc, f.auth.access["callers"][0]["actual_process"], observer_proc

    def _signed_checkpoint_rpc(
        self,
        auth_support,
        f,
        *,
        caller_id: str,
        operation: str,
        nonce_hex: str,
        issued_sec: int,
        deadline_sec: int,
    ) -> dict:
        if operation == "READ_CURRENT":
            body: dict = {"minimum_generation": 0, "minimum_head_sha256": "0" * 64, "consumption_binding": None}
        elif operation == "ADVANCE":
            body = {
                "transition_utf8": "{}",
                "transition_attestation_utf8": "{}",
                "initial_authorization_utf8": None,
                "unsigned_budget_utf8": "{}",
                "output_body_utf8": None,
                "output_attestation_utf8": None,
            }
        else:
            body = {
                "transition_id": "tr-1",
                "exact_request_sha256": "1" * 64,
                "minimum_generation": 0,
                "minimum_head_sha256": "0" * 64,
            }
        req = ck.validate(
            "CheckpointRpcRequest",
            {
                "format": "forex.checkpoint-rpc-request/2",
                "request_id": f"req-{caller_id}-{nonce_hex[:8]}",
                "binding": f.binding,
                "original_setup_key": f.original,
                "caller_id": caller_id,
                "operation": operation,
                "nonce_hex": nonce_hex,
                "issued": auth_support.stamp(issued_sec),
                "deadline": auth_support.stamp(deadline_sec),
                "body": body,
                "use": "SETUP_PROTOCOL",
            },
        ).payload()
        return auth_support.signed_rpc(req, ck.REQUEST_DOMAIN, f.keys[caller_id])

    def test_finding_11_per_principal_quota_expiry_and_durable_advance_replay_protection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "checkpoint_replay.sqlite3"
            auth_support, f, store, svc, peer_a, peer_b = self._build_two_principal_checkpoint_service(
                db_path,
                per_principal_read_capacity=6,
                per_principal_rate_limit=6,
            )

            # 1. Principal A fills its entire dedicated 6-entry read quota at t=1 (deadline=10)
            f.clock.now = auth_support.stamp(1)
            old_env_a0 = None
            for i in range(6):
                env = self._signed_checkpoint_rpc(
                    auth_support,
                    f,
                    caller_id="consumer",
                    operation="READ_CURRENT",
                    nonce_hex=f"{i + 1:064x}",
                    issued_sec=1,
                    deadline_sec=10,
                )
                if old_env_a0 is None:
                    old_env_a0 = env
                resp, _ = svc.handle(env, actual_peer=peer_a, now=f.clock.now)
                self.assertIn("ABSENT", resp["body_utf8"])

            # 7th request from Principal A is rejected by Principal A's own quota/rate limit
            env_a_over = self._signed_checkpoint_rpc(
                auth_support,
                f,
                caller_id="consumer",
                operation="READ_CURRENT",
                nonce_hex=f"{99:064x}",
                issued_sec=1,
                deadline_sec=10,
            )
            with self.assertRaises(AuthorityError) as ctx_over:
                svc.handle(env_a_over, actual_peer=peer_a, now=f.clock.now)
            self.assertEqual(ctx_over.exception.code, "REPLAY_OR_EQUIVOCATION")

            # Principal B retains full independent service despite Principal A exhausting its quota!
            env_b = self._signed_checkpoint_rpc(
                auth_support,
                f,
                caller_id="observer",
                operation="READ_CURRENT",
                nonce_hex=f"{501:064x}",
                issued_sec=1,
                deadline_sec=10,
            )
            resp_b, _ = svc.handle(env_b, actual_peer=peer_b, now=f.clock.now)
            self.assertIn("ABSENT", resp_b["body_utf8"])

            # 2. Advance past t=10 deadline -> old replay rejected with SETUP_DEADLINE_EXPIRED,
            #    expired read entries safely purge, and Principal A regains capacity!
            f.clock.now = auth_support.stamp(12)
            with self.assertRaises(AuthorityError) as ctx_exp:
                svc.handle(old_env_a0, actual_peer=peer_a, now=f.clock.now)
            self.assertEqual(ctx_exp.exception.code, "SETUP_DEADLINE_EXPIRED")

            removed = svc.expire_replay_windows(now=f.clock.now)
            self.assertEqual(removed, 7)  # 6 from A + 1 from B
            stats = svc.replay_cache_stats()
            self.assertEqual(stats["consumer"]["active_read_nonces"], 0)
            self.assertEqual(stats["observer"]["active_read_nonces"], 0)

            env_a_fresh = self._signed_checkpoint_rpc(
                auth_support,
                f,
                caller_id="consumer",
                operation="READ_CURRENT",
                nonce_hex=f"{1001:064x}",
                issued_sec=12,
                deadline_sec=20,
            )
            resp_a_fresh, _ = svc.handle(env_a_fresh, actual_peer=peer_a, now=f.clock.now)
            self.assertIn("ABSENT", resp_a_fresh["body_utf8"])

            # 3. Mutating ADVANCE nonce remains rejected across cache maintenance AND service recreation!
            adv_nonce = "aa" * 32
            env_adv = self._signed_checkpoint_rpc(
                auth_support,
                f,
                caller_id="consumer",
                operation="ADVANCE",
                nonce_hex=adv_nonce,
                issued_sec=12,
                deadline_sec=20,
            )
            resp_adv, _ = svc.handle(env_adv, actual_peer=peer_a, now=f.clock.now)
            self.assertIn("COMMITTED", resp_adv["body_utf8"])

            # Advance past deadline & run cache maintenance
            f.clock.now = auth_support.stamp(25)
            svc.expire_replay_windows(now=f.clock.now)
            self.assertEqual(svc.replay_cache_stats()["consumer"]["durable_advance_nonces"], 1)

            # Re-signed ADVANCE reusing the same nonce_hex with a fresh deadline MUST STILL BE REJECTED
            env_adv_replay = self._signed_checkpoint_rpc(
                auth_support,
                f,
                caller_id="consumer",
                operation="ADVANCE",
                nonce_hex=adv_nonce,
                issued_sec=25,
                deadline_sec=40,
            )
            with self.assertRaises(AuthorityError) as ctx_adv:
                svc.handle(env_adv_replay, actual_peer=peer_a, now=f.clock.now)
            self.assertEqual(ctx_adv.exception.code, "REPLAY_OR_EQUIVOCATION")

            # Recreate fresh CheckpointService against the same SQLite DB -> durable replay ledger STILL rejects!
            svc_restarted = CheckpointService(
                authentication=f.auth,
                store=store,
                signer=f.checkpoint_signer,
                peers=SimpleNamespace(observe=lambda selected: selected),
                own_process=auth_support.process("CHECKPOINT_CUSTODIAN", os.getpid(), 1002),
            )
            with self.assertRaises(AuthorityError) as ctx_adv2:
                svc_restarted.handle(env_adv_replay, actual_peer=peer_a, now=f.clock.now)
            self.assertEqual(ctx_adv2.exception.code, "REPLAY_OR_EQUIVOCATION")

    # =========================================================================
    # Finding [12]: emergency_close_all OANDA Parity & Drawdown Preserves CLOSE/REDUCE
    # =========================================================================

    def test_finding_12_emergency_close_all_closes_oanda_and_mt5_during_drawdown(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            gate = load_default_forex_valve_gate()

            # Configure 15% drawdown (peak=$100,000 -> current=$85,000): exceeds 10% hard cutoff
            # so OPEN is strictly vetoed while risk-reducing CLOSE/REDUCE remain operational.
            oanda_transport = _FakeOandaRestTransport(
                nav=Decimal("68000.00"),
                trades=[
                    {
                        "id": "771001",
                        "instrument": "GBP_USD",
                        "currentUnits": "10000",
                        "price": "1.27000",
                        "unrealizedPL": "-49.00",
                        "state": "OPEN",
                        "stopLossOrder": {"price": "1.26000"},
                        "takeProfitOrder": {"price": "1.28000"},
                    }
                ],
            )
            oanda_client = OandaPracticePaperClient(
                environ={
                    ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                    ENV_OANDA_PRACTICE_TOKEN: SYNTH_API_KEY,
                    ENV_OANDA_PRACTICE_ACCOUNT_ID: "101-001-9988776-001",
                },
                transport=oanda_transport,
                mutation_journal=OandaMutationJournal(root / "oanda_journal.sqlite3"),
                clock=lambda: T0,
            )
            oanda_venue = OandaPracticeFallbackVenue(
                client=oanda_client,
                valve_gate=gate,
                clock=lambda: T0,
            )
            oanda_venue.connect()

            mt5_pos = SimpleNamespace(
                ticket=55001,
                symbol="EURUSD",
                type=0,
                volume=Decimal("0.10"),
                price_open=Decimal("1.10000"),
                sl=Decimal("1.09000"),
                tp=Decimal("1.11000"),
                profit=Decimal("-50.00"),
            )
            mt5_sdk = _FakeMt5SdkForClose(
                1002903,
                "Hugosway-Demo",
                balance=Decimal("17050.00"),
                equity=Decimal("17000.00"),
                positions=[mt5_pos],
            )
            mt5_venue = Mt5PaperBrokerVenue(
                broker_id=BROKER_HUGOSWAY_MT5,
                credentials=Mt5Credentials(
                    broker_id=BROKER_HUGOSWAY_MT5,
                    login=1002903,
                    server="Hugosway-Demo",
                    password=_RedactedSecret(SYNTH_API_KEY),
                    execution_mode=EXECUTION_MODE_DEMO,
                ),
                transport=Mt5NativePythonTransport(mt5_module=mt5_sdk, clock=lambda: T0),
                valve_gate=gate,
                clock=lambda: T0,
            )
            mt5_venue.connect()

            oracle = OandaQuoteTruthOracle.from_static_quotes({
                "EURUSD": (Decimal("1.09500"), Decimal("1.09510")),
                "GBPUSD": (Decimal("1.26500"), Decimal("1.26520")),
            })
            router = DualShieldBrokerRouter(
                environ={ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO},
                valve_gate=gate,
                oracle=oracle,
                initial_peak_equity=Decimal("100000.00"),
                clock=lambda: T0,
            )
            router.attach_venue(mt5_venue)
            router.attach_venue(oanda_venue)

            # Confirm 15% drawdown blocks new OPEN
            with self.assertRaises(BarbellPolicyRefusalError):
                router.barbell.require_drawdown(
                    current_equity=router.barbell.total_equity(router.equities()),
                    peak_equity=Decimal("100000.00"),
                )

            trader = AutonomousAiTrader(
                router=router,
                model_registry=FrontierModelRegistry(environ={}),
                valve_gate=gate,
                quota_store=DailyQuotaGovernanceStore(path=root / "quota.sqlite3"),
                execution_gate=DurableModelExecutionGate(root / "model_gate.sqlite3", clock=lambda: T0),
                clock=lambda: T0,
            )

            # Verify partial REDUCE on OANDA succeeds under 15% drawdown before emergency close
            st_ref = trader._build_state_ref(T0)
            reduce_intent = ActionIntent(
                intent_id="intent-oanda-reduce-1",
                scope=trader._scope,
                decision_id="dec-oanda-reduce-1",
                opportunity_id="opp-oanda-reduce-1",
                action_ref="oanda-reduce-771",
                source_state=st_ref,
                kind=ActionKind.REDUCE,
                instrument_id="GBPUSD",
                origin=DecisionOrigin.OWNER_REVIEWED,
                created_at=T0,
                expires_at=st_ref.valid_until,
                quantity=Decimal("4000"),
                side=Side.SELL,
                target_id="771001",
                target_version=1,
            )
            reduce_dec = trader._make_valve_request_and_clear(
                intent=reduce_intent,
                strategy_id="overseer-reduce",
                timeframe="M1",
                label="Reduce OANDA 771001",
                reason="Partial risk reduction during 15% drawdown",
                bid=Decimal("1.26500"),
                ask=Decimal("1.26520"),
                total_eq=Decimal("85000.00"),
                peak_eq=Decimal("100000.00"),
                position_side=Side.BUY,
                now=T0,
            )
            reduce_order = OrderIntent.from_action_intent(reduce_intent, symbol="GBPUSD", position_ticket="771001")
            router.execute_management(BROKER_OANDA_PRACTICE, reduce_order, valve_decision=reduce_dec)
            self.assertEqual(len(oanda_transport.close_calls), 1)
            self.assertEqual(oanda_transport.close_calls[0][2]["units"], "4000")
            self.assertEqual(oanda_transport.trades["771001"]["currentUnits"], "6000")

            # Now invoke emergency_close_all() under 15% drawdown -> MUST close BOTH MT5 and OANDA!
            snap = trader.emergency_close_all(reason="Emergency halt under 15% drawdown", now=T0)
            self.assertIn("55001", snap["closed_tickets"])
            self.assertIn("771001", snap["closed_tickets"])
            self.assertEqual(len(mt5_sdk.positions), 0)
            self.assertEqual(len(oanda_transport.trades), 0)
            self.assertEqual(len(oanda_transport.close_calls), 2)
            self.assertEqual(oanda_transport.close_calls[1][2]["units"], "ALL")
            # OANDA mutation journal durably recorded both confirmed risk-reducing operations
            self.assertFalse(oanda_venue.mutation_journal.has_any_unresolved_mutation())


if __name__ == "__main__":
    unittest.main()
