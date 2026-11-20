"""E2E FA-6: CI / ui/package.json Parity & FrontierModelRegistry Circuit Breaker / Retry / Metering (10 tests)."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from cas_forex_revamp.contracts import (
    ActionIntent,
    ActionKind,
    DecisionFact,
    DecisionOrigin,
    DecisionRequest,
    EvidenceKind,
    EvidenceReference,
    RunScope,
    Side,
    StateReference,
    canonical_bytes,
    content_digest,
)
from cas_forex_revamp.operator.frontier_backends import (
    FRONTIER_MODEL_CATALOG,
    FrontierConfigurationError,
    FrontierModelRegistry,
    FrontierTransportError,
    _RedactedSecret,
    _validate_frontier_https_url,
    assert_safe_ai_catalog_payload,
)
from cas_forex_revamp.operator.model import (
    ActualModelDecisionAdapter,
    InferenceBudget,
)

try:
    from tests.e2e_hardening._e2e_support import (
        D,
        REPO_ROOT,
        SYNTH_API_KEY,
        SteppingClock,
        T0,
        clean_demo_environ,
        require_or_skip_unmerged,
        stub_frontier_http_post,
    )
except ImportError:  # pragma: no cover
    from _e2e_support import (
        D,
        REPO_ROOT,
        SYNTH_API_KEY,
        SteppingClock,
        T0,
        clean_demo_environ,
        require_or_skip_unmerged,
        stub_frontier_http_post,
    )


def _sample_decision_request(request_id: str = "req-e2e-frontier") -> DecisionRequest:
    scope = RunScope("acct-e2e", "run-e2e", 1, "b1", "p1", "s1", "adapter-e2e")
    st = StateReference("st-e2e", scope, 1, T0, T0.replace(minute=5), 1)
    intent = ActionIntent(
        intent_id="ai-ord-e2e-1",
        scope=scope,
        decision_id="dec-e2e-1",
        opportunity_id="opp-e2e-1",
        action_ref="opt-0",
        kind=ActionKind.OPEN,
        origin=DecisionOrigin.ACTUAL_MODEL,
        instrument_id="NAS100",
        source_state=st,
        created_at=T0,
        expires_at=T0.replace(minute=5),
        quantity=D("1"),
        side=Side.BUY,
        limit_price=D("20502.50"),
        stop_price=D("20475.00"),
        take_profit_price=D("20560.00"),
    )
    fact_obj = {"sym": "NAS100", "bid": "20500.00", "ask": "20502.50"}
    return DecisionRequest(
        request_id=request_id,
        opportunity_set_id="set-e2e-frontier",
        state=st,
        options=(),
        facts=(DecisionFact("f-1", "quote", canonical_bytes(fact_obj).decode("utf-8"), ("ev-1",)),),
        evidence=(EvidenceReference("ev-1", EvidenceKind.OBSERVATION, "test", content_digest(fact_obj), T0),),
    )


class CiAndFrontierE2ETests(unittest.TestCase):
    # --- Tier 1: Feature Coverage (E2E-T1-26 .. E2E-T1-30) ---

    def test_e2e_t1_26_ui_package_json_valid_and_m3_test_parity(self) -> None:
        pkg = json.loads((REPO_ROOT / "ui/package.json").read_text(encoding="utf-8"))
        self.assertEqual(pkg.get("type"), "module")
        self.assertEqual((pkg.get("engines") or {}).get("node"), ">=22")
        script = str((pkg.get("scripts") or {}).get("test") or "")
        committed = sorted(p.name for p in (REPO_ROOT / "tests/ui").glob("*.test.mjs"))
        missing = [name for name in committed if name not in script]
        if missing:
            require_or_skip_unmerged(
                self,
                f"ui/package.json scripts.test missing committed tests/ui files: {', '.join(missing)} (M3)",
            )
        self.assertEqual(missing, [])

    def test_e2e_t1_27_ci_configs_include_pytest_node_bandit_pip_audit(self) -> None:
        gitlab_ci = (REPO_ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
        gh_ci = (REPO_ROOT / "docs/github-workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("pytest", gitlab_ci)
        self.assertIn("node --test", gitlab_ci)
        self.assertIn("bandit -r src", gitlab_ci)
        self.assertIn("pip-audit -r requirements.txt", gitlab_ci)
        if "tests/security" not in gh_ci:
            require_or_skip_unmerged(self, "docs/github-workflows/ci.yml tests/security inclusion (M3)")

    def test_e2e_t1_28_frontier_catalog_has_exact_nine_models_and_providers(self) -> None:
        reg = FrontierModelRegistry(
            environ=clean_demo_environ(),
            http_post=stub_frontier_http_post,
            resolve_dns=lambda _h: None,
        )
        snap = assert_safe_ai_catalog_payload(reg.catalog_snapshot())
        models = snap["models"]
        self.assertEqual(len(models), 9)
        expected_ids = [
            "claude-fable-5.2",
            "claude-fable",
            "claude-5.5",
            "gemini-decision-1",
            "gemini-carbon",
            "gemini-argon",
            "openai-astra",
            "deepseek-flash-1017",
            "qwen3:0.6b",
        ]
        self.assertEqual([m["model_id"] for m in models], expected_ids)
        providers = {m["provider"] for m in models}
        self.assertEqual(providers, {"anthropic", "gemini_decision", "gemini", "openai", "deepseek", "ollama"})

    def test_e2e_t1_29_frontier_backend_infer_updates_catalog_and_redacts_secrets(self) -> None:
        def stub_post(url: str, headers: dict[str, str], body: bytes, timeout: float, max_bytes: int):
            body_doc = json.loads(body.decode("utf-8"))
            user_doc = json.loads(body_doc["messages"][-1]["content"])
            sel = {
                "request_id": user_doc["request_id"],
                "opportunity_set_id": user_doc["opportunity_set_id"],
                "source_state_id": user_doc["state"]["state_id"],
                "selected_action_ref": None,
                "reason": "ID=0wait_none Spread wait",
                "evidence_ids": ["ev-1"],
            }
            return 200, json.dumps({
                "choices": [{"message": {"content": json.dumps(sel)}}],
                "usage": {"prompt_tokens": 120, "completion_tokens": 30},
            }).encode("utf-8")

        clk = SteppingClock(T0)
        env = clean_demo_environ(CAS_FOREX_OPENAI_API_KEY=SYNTH_API_KEY)
        reg = FrontierModelRegistry(
            environ=env,
            clock=clk,
            http_post=stub_post,
            ollama_http_post=stub_post,
            resolve_dns=lambda _h: None,
        )
        spec, backend, verifier = reg.build_backend("openai-astra")
        budget = InferenceBudget(
            max_calls=1,
            max_input_tokens_per_call=16384,
            max_generated_tokens_per_call=256,
            max_seconds_per_call=10,
            max_total_seconds=10,
        )
        adapter = ActualModelDecisionAdapter(
            adapter_id="e2e-openai-astra",
            model=spec,
            budget=budget,
            backend=backend,
            receipt_verifier=verifier,
            execution_gate=lambda _: None,
            clock=clk,
        )
        out = adapter.decide(_sample_decision_request())
        self.assertIsNone(out.selection.selected_action_ref)
        self.assertEqual(len(out.provenance.response_sha256), 64)
        reg.record_call("openai-astra", status="OK", latency_ms=42)
        snap = assert_safe_ai_catalog_payload(reg.catalog_snapshot())
        self.assertNotIn(SYNTH_API_KEY, json.dumps(snap))
        oai_item = next(m for m in snap["models"] if m["model_id"] == "openai-astra")
        self.assertGreaterEqual(int(oai_item["calls"]), 1)

    def test_e2e_t1_30_scout_opportunities_and_read_only_explainer_answer(self) -> None:
        def stub_post(url: str, headers: dict[str, str], body: bytes, timeout: float, max_bytes: int):
            doc = json.loads(body.decode("utf-8"))
            if "messages" in doc:
                return 200, json.dumps({
                    "content": [{"type": "text", "text": json.dumps({"answer": "DEMO valve gate active."})}],
                    "usage": {"output_tokens": 25},
                }).encode("utf-8")
            return 200, json.dumps({
                "decisions": [{"market": "NAS100", "choice": "ENTER_LONG", "probability": "0.91"}]
            }).encode("utf-8")

        env = clean_demo_environ(
            CAS_FOREX_ANTHROPIC_API_KEY=SYNTH_API_KEY,
            CAS_FOREX_GEMINI_API_KEY=SYNTH_API_KEY,
        )
        reg = FrontierModelRegistry(
            environ=env,
            clock=SteppingClock(T0),
            http_post=stub_post,
            ollama_http_post=stub_post,
            resolve_dns=lambda _h: None,
        )
        scout = reg.scout_opportunities([
            {"market": "NAS100", "spread_ok": True},
            {"market": "EURUSD", "spread_ok": True},
        ])
        self.assertTrue(scout["executed"])
        self.assertEqual(scout["best_market"], "NAS100")

        ans = reg.answer_explainer_question(
            question="Are any live orders enabled?",
            context_summary={"execution_mode": "DEMO", "active_broker": "HUGOSWAY_MT5"},
        )
        self.assertTrue(ans["read_only"])
        self.assertEqual(ans["schema"], "cas-forex.explainer-answer/1")

    # --- Tier 2: Boundary & Corner Cases (E2E-T2-26 .. E2E-T2-30) ---

    def test_e2e_t2_26_ui_package_json_references_only_existing_committed_ui_tests(self) -> None:
        pkg = json.loads((REPO_ROOT / "ui/package.json").read_text(encoding="utf-8"))
        script = str((pkg.get("scripts") or {}).get("test") or "")
        refs = [tok for tok in script.split() if tok.endswith(".test.mjs")]
        self.assertTrue(refs)
        for rel in refs:
            target = (REPO_ROOT / "ui" / rel).resolve()
            self.assertTrue(target.is_file(), f"ui/package.json references missing UI test: {rel}")

    def test_e2e_t2_27_gitlab_ci_lantern_analyze_must_fail_closed_in_m4(self) -> None:
        gitlab_ci = (REPO_ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
        lantern_lines = [line.strip() for line in gitlab_ci.splitlines() if "lantern analyze" in line]
        self.assertTrue(lantern_lines)
        if any("|| true" in line for line in lantern_lines):
            require_or_skip_unmerged(self, ".gitlab-ci.yml fail-closed lantern analyze without '|| true' (M3)")

    def test_e2e_t2_28_frontier_consecutive_503_429_circuit_breaker_and_retry(self) -> None:
        calls = 0

        def failing_post(url: str, headers: dict[str, str], body: bytes, timeout: float, max_bytes: int):
            nonlocal calls
            calls += 1
            return 503, b'{"error":{"message":"overloaded"}}'

        clk = SteppingClock(T0)
        env = clean_demo_environ(CAS_FOREX_OPENAI_API_KEY=SYNTH_API_KEY)
        reg = FrontierModelRegistry(
            environ=env,
            clock=clk,
            http_post=failing_post,
            ollama_http_post=failing_post,
            resolve_dns=lambda _h: None,
        )
        snap_cb = reg.catalog_snapshot()
        has_cb = (
            "circuit_breakers" in snap_cb
            and "provider_spend" in snap_cb
            and "total_spend_micro_usd" in snap_cb
        )
        if not has_cb:
            require_or_skip_unmerged(
                self,
                "FrontierModelRegistry/FrontierChatBackend circuit breaker, jittered retry & spend metering (M3)",
            )
        spec, backend, verifier = reg.build_backend("openai-astra")
        budget = InferenceBudget(
            max_calls=10,
            max_input_tokens_per_call=16384,
            max_generated_tokens_per_call=256,
            max_seconds_per_call=10,
            max_total_seconds=60,
        )
        adapter = ActualModelDecisionAdapter(
            adapter_id="e2e-cb",
            model=spec,
            budget=budget,
            backend=backend,
            receipt_verifier=verifier,
            execution_gate=lambda _: None,
            clock=clk,
        )
        for idx in range(5):
            with self.assertRaises(FrontierTransportError):
                adapter.decide(_sample_decision_request(request_id=f"req-e2e-cb-{idx}"))
        snap_after = reg.catalog_snapshot()
        self.assertEqual(snap_after["circuit_breakers"]["openai"]["state"], "OPEN")
        calls_before_open = calls
        with self.assertRaises(FrontierTransportError):
            adapter.decide(_sample_decision_request(request_id="req-e2e-cb-open-probe"))
        self.assertEqual(calls, calls_before_open)

    def test_e2e_t2_29_frontier_url_validation_rejects_non_allowlisted_host_or_http(self) -> None:
        with self.assertRaises((FrontierConfigurationError, FrontierTransportError)):
            _validate_frontier_https_url("https://evil.example/v1/messages", expected_host="api.anthropic.com")
        with self.assertRaises((FrontierConfigurationError, FrontierTransportError)):
            _validate_frontier_https_url("http://api.anthropic.com/v1/messages", expected_host="api.anthropic.com")

    def test_e2e_t2_30_unknown_model_invalid_question_and_redacted_secret_safe(self) -> None:
        reg = FrontierModelRegistry(
            environ=clean_demo_environ(),
            http_post=stub_frontier_http_post,
            resolve_dns=lambda _h: None,
        )
        with self.assertRaises(FrontierConfigurationError):
            reg.select_model("unknown-model-xyz")
        with self.assertRaises(FrontierConfigurationError):
            reg.answer_explainer_question(question="   ")
        with self.assertRaises(FrontierConfigurationError):
            reg.answer_explainer_question(question="q" * 501)

        secret = _RedactedSecret(SYNTH_API_KEY)
        self.assertNotIn(SYNTH_API_KEY, repr(secret))
        self.assertNotIn(SYNTH_API_KEY, str(secret))
        self.assertNotIn(SYNTH_API_KEY, f"{secret}")


if __name__ == "__main__":
    unittest.main()
