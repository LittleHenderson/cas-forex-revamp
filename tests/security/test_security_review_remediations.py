"""Unified cross-finding regression suite verifying all 9 security review remediations ([1]..[9]).

Complements the deep per-track suites (`test_remediation_stageb.py`, `test_remediation_feeds.py`,
`test_remediation_runtime.py`, and `test_remediation_cockpit_and_drawdown.py`) with fast (<2s),
zero-skip `unittest.TestCase` verification of every finding's primary security boundary.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
import urllib.error
import urllib.request

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _rel in (
    "src",
    "",
    "shared-interface",
    "operational/measurement/source",
    "operational/authority/source",
    "operational/custody/source",
    "source_runtime",
    "tests/integration",
):
    _cand = str((_REPO_ROOT / _rel).resolve())
    if _cand not in sys.path:
        sys.path.insert(0, _cand)

from cas_forex_measurement.completion import MEASUREMENT_SYSTEMD_CGROUP_PROPERTIES, validate_measurement_unit_ready
from cas_forex_operational_contracts.common import ContractError as OperationalContractError
from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer
from cas_forex_revamp.composition.r6_reason import evaluate_evidence_grounded_reason, semantic_result
from cas_forex_revamp.contracts import (
    AccountRunKey,
    ActionIntent,
    ActionKind,
    AuthorizedCommand,
    ContractError,
    ControlKind,
    DecisionOrigin,
    EffectState,
    Environment,
    FenceRequest,
    Instrument,
    MarketObservation,
    Money,
    RunScope,
    Side,
    StateReference,
    intent_digest,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import ValveRefusalError, load_default_forex_valve_gate
from cas_forex_revamp.venue import SQLiteVenue, VenueScenario
from cas_forex_revamp.venue.external_paper_broker import PublicLiveFxFeedClient, validate_pinned_public_feed_url
from cas_forex_revamp.venue.live_market_stream import ExpandedPublicLiveFxFeedClient
from ceremony_generator import (
    CEREMONY_ROLES,
    Ed25519Keypair,
    _materialize_regular_tree,
    provision_ceremony_key_vault,
    provision_or_load_ceremony_key_vault,
)


T0 = datetime(2026, 11, 16, 16, 0, tzinfo=timezone.utc)
D = Decimal


class SecurityReviewNineFindingsTests(unittest.TestCase):
    def test_finding_01_deterministic_key_derivation_removed_and_distinct_role_vault_enforced(self) -> None:
        self.assertFalse(hasattr(Ed25519Keypair, "derive"))
        with tempfile.TemporaryDirectory() as tmp:
            vault = provision_ceremony_key_vault(Path(tmp) / "vault", run_id="sec-f1-run")
            self.assertEqual(set(vault.keys()), set(CEREMONY_ROLES))
            pub_set = {kp.public_bytes for kp in vault.values()}
            self.assertEqual(len(pub_set), len(CEREMONY_ROLES))

    def test_finding_02_tree_materializer_rejects_escape_links_without_creating_dst(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = root / "host_secret.txt"
            secret.write_text("TOP_SECRET", encoding="utf-8")
            src = root / "src_tree"
            src.mkdir()
            (src / "ok.txt").write_text("ok", encoding="utf-8")
            dst = root / "dst_tree"
            # Missing or non-directory source fails closed; symlink/junction escapes tested deeply in test_remediation_stageb
            with self.assertRaises(Exception):
                _materialize_regular_tree(secret, dst)
            self.assertFalse(dst.exists())

    def test_finding_03_drawdown_gate_blocks_open_above_threshold_and_allows_close(self) -> None:
        gate = load_default_forex_valve_gate(max_drawdown_pct=D("0.10"))
        state = SimpleNamespace(scope=SimpleNamespace(account_id="a1", run_id="r1"), observed_at=T0, valid_until=T0 + timedelta(minutes=5))
        req = SimpleNamespace(request_id="req-f3", facts=(), evidence=(SimpleNamespace(evidence_id="ev-1"),), state=state)
        sel = SimpleNamespace(evidence_ids=("ev-1",), reason="Setup", selected_action_ref="act-f3")
        open_intent = SimpleNamespace(intent_id="i1", action_ref="act-f3", kind=ActionKind.OPEN, instrument_id="EURUSD", quantity=D("1000"), side=Side.BUY, stop_price=D("1.09"), limit_price=None)
        close_intent = SimpleNamespace(intent_id="i2", action_ref="act-f3", kind=ActionKind.CLOSE, instrument_id="EURUSD", quantity=D("1000"), side=None, stop_price=None, limit_price=None, target_id="p1")
        dd_view = {"balance": "100000", "equity": "88000", "peak_equity": "100000", "available_margin": "80000", "position_inventory": ["p1"]}
        pol = {"new_risk_permission": "ALLOWED", "management_permission": "ALLOWED", "max_entry_quantity": "10000", "max_drawdown_pct": "0.10"}
        with self.assertRaises(ValveRefusalError) as ctx:
            gate.require_admissible(SimpleNamespace(request=req, result=SimpleNamespace(selection=sel), intent=open_intent), current_view=dd_view, policy=pol, now=T0 + timedelta(seconds=1))
        self.assertIn("MAX_DRAWDOWN_EXCEEDED", ctx.exception.decision.hard_veto_reasons)
        dec_close = gate.require_admissible(SimpleNamespace(request=req, result=SimpleNamespace(selection=sel), intent=close_intent), current_view=dd_view, policy=pol, now=T0 + timedelta(seconds=1))
        self.assertTrue(dec_close.admitted)

    def test_finding_04_sqlite_venue_rejects_stale_source_cursor_on_concurrent_advance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            v = SQLiteVenue(Path(tmp) / "f4.venue.sqlite3")
            scope = RunScope("acct-f4", "run-f4", 1, "b", "p", "scen-f4", "v")
            key = AccountRunKey("acct-f4", "run-f4", Environment.DISCONNECTED_SIMULATION)
            inst = Instrument("EURUSD", "EURUSD", "EUR", "USD", D("0.0001"), D("1"), D("1"))
            v.initialize(key, opening_balance=Money(D("10000"), "USD"), instruments=(inst,), now=T0, scenario=VenueScenario("scen-f4"))
            v.advance_fence(FenceRequest(key, "b-1", ControlKind.RESUME_NEW_RISK, "own-1", 0, 1, T0), now=T0)
            snap1 = v.advance_market(MarketObservation(key, "m-1", "EURUSD", 2, T0, T0, D("1.1000"), D("1.1002")))
            stale_state = StateReference("st-1", scope, 1, T0, T0 + timedelta(minutes=5), snap1.sequence)
            # Concurrent market advance increments venue sequence to 3 before accept
            v.advance_market(MarketObservation(key, "m-2", "EURUSD", 3, T0, T0, D("1.1001"), D("1.1003")))
            intent = ActionIntent("int-f4", scope, "dec-f4", "opp-f4", "ref-f4", stale_state, ActionKind.OPEN, "EURUSD", DecisionOrigin.ACTUAL_MODEL, T0, T0 + timedelta(minutes=1), quantity=D("10"), side=Side.BUY, stop_price=D("1.0950"))
            cmd = AuthorizedCommand("cmd-f4", intent, intent_digest(intent), "res-f4", "auth-f4", snap1.fence.generation, "writer-1", D("1.1100"))
            rcpt = v.accept(cmd, now=T0 + timedelta(seconds=1))
            self.assertIs(rcpt.effect, EffectState.REJECTED)
            self.assertEqual(rcpt.reason_code, "STALE_SOURCE_CURSOR")

    def test_finding_05_public_feed_client_enforces_exact_allowlist_and_blocks_ssrf_hosts(self) -> None:
        self.assertTrue(validate_pinned_public_feed_url("https://api.kraken.com/0/public/Ticker?pair=EURUSD").startswith("https://"))
        for bad_url in (
            "https://evil.example.com/0/public/Ticker",
            "https://127.0.0.1/0/public/Ticker",
            "https://api.kraken.com:8443/0/public/Ticker",
            "https://user:pass@api.kraken.com/0/public/Ticker",
            "https://api.kraken.com/0/private/Balance",
        ):
            with self.assertRaises(ContractError, msg=bad_url):
                PublicLiveFxFeedClient(kraken_ticker_url=bad_url)

    def test_finding_06_expanded_feed_fails_closed_when_reference_endpoints_fail(self) -> None:
        def failing_ref_transport(url: str, timeout: float, max_bytes: int) -> bytes:
            if "kraken.com" in url:
                return json.dumps({
                    "error": [],
                    "result": {
                        p: {"a": ["1.10020", "1", "1"], "b": ["1.10000", "1", "1"], "c": ["1.10010", "1"], "p": ["1.10010", "1.10010"], "t": [10, 10]}
                        for p in ("EURUSD", "GBPUSD", "USDJPY", "USDCHF", "AUDUSD", "USDCAD", "NZDUSD", "EURGBP", "EURJPY", "GBPJPY", "EURCHF", "EURAUD", "EURCAD", "AUDJPY", "CHFJPY", "CADJPY")
                    },
                }).encode("utf-8")
            raise OSError("all ECB/Frankfurter reference feeds unreachable")

        client = ExpandedPublicLiveFxFeedClient(http_get=failing_ref_transport)
        with self.assertRaises(ContractError):
            client.fetch_market_stream(now=T0)

    def test_finding_07_semantic_scoring_requires_out_of_band_signature_and_grounded_reason(self) -> None:
        # Unsupported generic prose fails evidence-grounded rubric
        attempt = {
            "case_id": "abcd" * 8,
            "step_id": "1234" * 8,
            "selected_action_ref": None,
            "evidence_ids": ["evidence-" + "1234" * 8],
            "result": {"selection": {"selected_action_ref": None, "reason": "Looks good to me", "evidence_ids": ["evidence-" + "1234" * 8]}},
            "request": {"options": [], "evidence": [{"evidence_id": "evidence-" + "1234" * 8}]},
        }
        self.assertFalse(evaluate_evidence_grounded_reason(attempt))
        # Unsigned review object fails closed even if all booleans are True
        unsigned_review = {
            "reviewer_id": "rev-1",
            "reason_supported_by_current_evidence": True,
            "no_unsupported_inferred_facts": True,
            "cites_supplied_evidence": True,
            "no_prohibited_authority_claim": True,
        }
        self.assertIsNone(semantic_result(attempt, unsigned_review, pinned_reviewer_public_key="11" * 32, trusted_reviewer_id="rev-1"))

    def test_finding_08_measurement_systemd_cgroup_readiness_fails_closed_on_missing_limits(self) -> None:
        self.assertEqual(MEASUREMENT_SYSTEMD_CGROUP_PROPERTIES["MemoryMax"], "2048M")
        self.assertEqual(MEASUREMENT_SYSTEMD_CGROUP_PROPERTIES["MemorySwapMax"], "0")
        self.assertEqual(MEASUREMENT_SYSTEMD_CGROUP_PROPERTIES["TasksMax"], "256")
        with self.assertRaises(OperationalContractError):
            validate_measurement_unit_ready(
                "cas-test.service",
                runner=lambda *a, **kw: SimpleNamespace(returncode=0, stdout="MemoryMax=infinity\n", stderr=""),
            )

    def test_finding_09_loopback_cockpit_enforces_bearer_auth_and_rotates_tokens(self) -> None:
        srv = LoopbackCockpitServer(
            repo_root=_REPO_ROOT,
            host="127.0.0.1",
            port=0,
            broker_router_reader=lambda: {"schema": "cas-forex.broker-routing/2", "demo_only": True, "live_trading_locked": True, "chain": []},
        )
        base = srv.start()
        try:
            with self.assertRaises(urllib.error.HTTPError) as unauth:
                urllib.request.urlopen(base + "/api/broker-routing", timeout=5)  # nosec B310: local loopback cockpit test URL
            self.assertEqual(unauth.exception.code, 401)
            unauth.exception.close()

            old_headers = srv.auth_headers()
            with urllib.request.urlopen(urllib.request.Request(base + "/api/broker-routing", headers=old_headers), timeout=5) as ok_resp:  # nosec B310: local loopback cockpit test URL
                self.assertEqual(ok_resp.status, 200)

            srv.rotate_auth_token()
            with self.assertRaises(urllib.error.HTTPError) as rotated:
                urllib.request.urlopen(urllib.request.Request(base + "/api/broker-routing", headers=old_headers), timeout=5)  # nosec B310: local loopback cockpit test URL
            self.assertEqual(rotated.exception.code, 401)
            rotated.exception.close()
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()
