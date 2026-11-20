"""Socket-free unit & contract tests for Frontier AI resilience, circuit breakers, and exact spend metering."""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import logging
from pathlib import Path
import ssl
import threading
import unittest
import urllib.error

from cas_forex_revamp.contracts import (
    ActionIntent,
    ActionKind,
    ActionOption,
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
    CircuitBreakerConfig,
    CircuitBreakerState,
    FRONTIER_MODEL_CATALOG,
    FrontierChatBackend,
    FrontierCircuitOpenError,
    FrontierConfigurationError,
    FrontierModelRegistry,
    FrontierOperationKind,
    FrontierReceiptVerifier,
    FrontierTransportError,
    SupervisedOllamaBinding,
    SupervisedOllamaReceiptSigner,
    ProviderCircuitBreaker,
    RetryPolicy,
    assert_safe_ai_catalog_payload,
    compute_call_cost_pico_usd,
    execute_resilient_frontier_call,
    pico_usd_to_decimal_text,
    pico_usd_to_micro_usd,
)
from cas_forex_revamp.operator.model import (
    ActualModelDecisionAdapter,
    InferenceBudget,
    ModelInvocation,
    OUTPUT_SCHEMA_ID,
    SYSTEM_POLICY,
)

T0 = datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)
STATE_DIGEST = "a" * 64


def _make_invocation(backend: FrontierChatBackend, spec, *, req_id: str = "req-1", max_seconds: int = 10) -> ModelInvocation:
    pkt = {
        "request_id": req_id,
        "opportunity_set_id": "set-1",
        "state": {"state_id": f"state-{STATE_DIGEST}", "equity": "10000"},
        "options": [{"action_ref": "opt-long-eurusd", "kind": "OPEN", "symbol": "EURUSD"}],
        "evidence": [{"evidence_id": "ev-1", "summary": "spread 0.8 pips"}],
    }
    pkt_json = canonical_bytes(pkt).decode("utf-8")
    inv_sha = content_digest({"req_id": req_id, "pkt": pkt_json})
    return ModelInvocation(
        request_sha256=inv_sha,
        model=spec,
        session_id="sess-resilience",
        system_policy=SYSTEM_POLICY,
        packet_json=pkt_json,
        budget=InferenceBudget(
            max_calls=100,
            max_input_tokens_per_call=16000,
            max_generated_tokens_per_call=512,
            max_seconds_per_call=max_seconds,
            max_total_seconds=60,
        ),
    )


def _anthropic_ok_body(req_id: str = "req-1", *, in_tokens: int = 120, out_tokens: int = 40) -> bytes:
    sel = {
        "request_id": req_id,
        "opportunity_set_id": "set-1",
        "source_state_id": f"state-{STATE_DIGEST}",
        "selected_action_ref": None,
        "reason": "ID=0wait_none",
        "evidence_ids": ["ev-1"],
    }
    return json.dumps({
        "content": [{"type": "text", "text": json.dumps(sel)}],
        "usage": {"input_tokens": in_tokens, "output_tokens": out_tokens},
    }).encode("utf-8")


def _openai_ok_body(req_id: str = "req-1", *, in_tokens: int = 80, out_tokens: int = 20) -> bytes:
    sel = {
        "request_id": req_id,
        "opportunity_set_id": "set-1",
        "source_state_id": f"state-{STATE_DIGEST}",
        "selected_action_ref": None,
        "reason": "ID=0wait_none",
        "evidence_ids": ["ev-1"],
    }
    return json.dumps({
        "choices": [{"message": {"content": json.dumps(sel)}}],
        "usage": {"prompt_tokens": in_tokens, "completion_tokens": out_tokens},
    }).encode("utf-8")


def _gemini_ok_body(req_id: str = "req-1", *, in_tokens: int = 60, out_tokens: int = 15) -> bytes:
    sel = {
        "request_id": req_id,
        "opportunity_set_id": "set-1",
        "source_state_id": f"state-{STATE_DIGEST}",
        "selected_action_ref": None,
        "reason": "ID=0wait_none",
        "evidence_ids": ["ev-1"],
    }
    return json.dumps({
        "candidates": [{"content": {"parts": [{"text": json.dumps(sel)}]}}],
        "usageMetadata": {"promptTokenCount": in_tokens, "candidatesTokenCount": out_tokens},
    }).encode("utf-8")


def _assert_no_floats(node: object, path: str = "$") -> None:
    if isinstance(node, float):
        raise AssertionError(f"unexpected float at {path}: {node!r}")
    if isinstance(node, dict):
        for k, v in node.items():
            _assert_no_floats(v, f"{path}.{k}")
    elif isinstance(node, (list, tuple)):
        for idx, item in enumerate(node):
            _assert_no_floats(item, f"{path}[{idx}]")


class FrontierResilienceTests(unittest.TestCase):
    def _test_secrets(self) -> dict[str, str]:
        return {
            "CAS_FOREX_ANTHROPIC_API_KEY": "sk-" + "ant-" + "sentinelKeyAlpha123456",
            "CAS_FOREX_GEMINI_API_KEY": "AIza" + "SentinelGemKeyBeta987654",
            "CAS_FOREX_OPENAI_API_KEY": "sk-" + "proj-" + "sentinelOaiGamma456789",
            "CAS_FOREX_DEEPSEEK_API_KEY": "sk-" + "ds-" + "sentinelDelta11223344",
        }

    def test_circuit_breaker_closed_open_half_open_recovery_and_reopen(self) -> None:
        now_box = [T0]
        sleeps: list[float] = []
        calls: list[str] = []
        mode = ["fail_503"]

        def fake_http(url: str, headers: dict, body: bytes, timeout: float, max_bytes: int):
            calls.append(url)
            if mode[0] == "fail_503":
                return 503, b'{"error":"overloaded"}'
            return 200, _anthropic_ok_body()

        reg = FrontierModelRegistry(
            environ=self._test_secrets(),
            clock=lambda: now_box[0],
            sleep=sleeps.append,
            http_post=fake_http,
            resolve_dns=lambda _h: None,
            circuit_breaker_config=CircuitBreakerConfig(failure_threshold=3, cooldown_seconds=Decimal("30")),
            retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=Decimal("0.01"), max_delay_seconds=Decimal("0.05")),
        )
        spec, backend, verifier = reg.build_backend("claude-fable-5.2")
        inv = _make_invocation(backend, spec)

        # 3 failed logical calls (2 attempts each) -> CLOSED -> OPEN
        for _ in range(3):
            with self.assertRaises(FrontierTransportError):
                backend.infer(inv)
        self.assertEqual(len(calls), 6)
        snap = reg.catalog_snapshot()
        self.assertEqual(snap["circuit_breakers"]["anthropic"]["state"], CircuitBreakerState.OPEN.value)
        self.assertEqual(snap["models"][0]["circuit_state"], "OPEN")

        # While OPEN before cooldown, calls fail fast with FrontierCircuitOpenError and 0 HTTP calls
        now_box[0] = T0 + timedelta(seconds=15)
        with self.assertRaises(FrontierCircuitOpenError) as ctx:
            backend.infer(inv)
        self.assertIsInstance(ctx.exception, FrontierTransportError)
        self.assertEqual(len(calls), 6)

        # Advance past cooldown -> HALF_OPEN single probe (max_attempts=1 even though RetryPolicy=2!)
        now_box[0] = T0 + timedelta(seconds=31)
        calls_before_probe = len(calls)
        with self.assertRaises(FrontierTransportError):
            backend.infer(inv)
        self.assertEqual(len(calls) - calls_before_probe, 1)
        self.assertEqual(reg.catalog_snapshot()["circuit_breakers"]["anthropic"]["state"], "OPEN")

        # Still within refreshed cooldown -> fast-fail again
        now_box[0] = T0 + timedelta(seconds=45)
        with self.assertRaises(FrontierCircuitOpenError):
            backend.infer(inv)
        self.assertEqual(len(calls) - calls_before_probe, 1)

        # Advance past second cooldown, let single probe succeed -> HALF_OPEN -> CLOSED
        now_box[0] = T0 + timedelta(seconds=62)
        mode[0] = "ok"
        reply = backend.infer(inv)
        self.assertTrue(verifier.verify(reply, inv))
        snap_ok = reg.catalog_snapshot()
        self.assertEqual(snap_ok["circuit_breakers"]["anthropic"]["state"], "CLOSED")
        self.assertEqual(snap_ok["circuit_breakers"]["anthropic"]["consecutive_failures"], 0)

    def test_half_open_single_flight_probe_blocks_concurrent_callers(self) -> None:
        now_box = [T0]
        probe_entered = threading.Event()
        release_probe = threading.Event()
        http_calls = 0
        calls_lock = threading.Lock()
        mode = ["fail"]

        def fake_http(url: str, headers: dict, body: bytes, timeout: float, max_bytes: int):
            nonlocal http_calls
            with calls_lock:
                http_calls += 1
            if mode[0] == "fail":
                return 503, b"{}"
            probe_entered.set()
            release_probe.wait(timeout=5.0)
            return 200, _anthropic_ok_body()

        reg = FrontierModelRegistry(
            environ=self._test_secrets(),
            clock=lambda: now_box[0],
            sleep=lambda _s: None,
            http_post=fake_http,
            resolve_dns=lambda _h: None,
            circuit_breaker_config=CircuitBreakerConfig(failure_threshold=2, cooldown_seconds=Decimal("10")),
            retry_policy=RetryPolicy(max_attempts=1),
        )
        spec, backend, _ = reg.build_backend("claude-fable-5.2")
        inv = _make_invocation(backend, spec)

        for _ in range(2):
            with self.assertRaises(FrontierTransportError):
                backend.infer(inv)
        self.assertEqual(http_calls, 2)

        # Expire cooldown so next caller acquires the single HALF_OPEN probe
        now_box[0] = T0 + timedelta(seconds=11)
        mode[0] = "block_ok"

        results: list[str] = []

        def run_probe() -> None:
            reply = backend.infer(inv)
            results.append(f"OK:{reply.receipt_id}")

        def run_contender() -> None:
            probe_entered.wait(timeout=5.0)
            try:
                backend.infer(inv)
                results.append("UNEXPECTED_OK")
            except FrontierCircuitOpenError:
                results.append("CIRCUIT_OPEN")

        with ThreadPoolExecutor(max_workers=4) as pool:
            f1 = pool.submit(run_probe)
            f2 = pool.submit(run_contender)
            f3 = pool.submit(run_contender)
            self.assertTrue(probe_entered.wait(timeout=5.0))
            f2.result(timeout=5.0)
            f3.result(timeout=5.0)
            release_probe.set()
            f1.result(timeout=5.0)

        self.assertEqual(http_calls, 3)
        self.assertEqual(results.count("CIRCUIT_OPEN"), 2)
        self.assertEqual(sum(1 for r in results if r.startswith("OK:")), 1)
        self.assertEqual(reg.catalog_snapshot()["circuit_breakers"]["anthropic"]["state"], "CLOSED")

    def test_provider_isolation_and_gemini_decide_404_fallback_does_not_trip(self) -> None:
        now_box = [T0]
        seen_urls: list[str] = []

        def fake_http(url: str, headers: dict, body: bytes, timeout: float, max_bytes: int):
            seen_urls.append(url)
            if "api.anthropic.com" in url:
                return 503, b'{"error":"down"}'
            if ":decide" in url:
                raise FrontierTransportError("frontier AI HTTP status 404")
            if ":generateContent" in url:
                if "batch_questions" in body.decode("utf-8") or "Screen candidate" in body.decode("utf-8"):
                    txt = json.dumps({"decisions": [{"market": "NAS100", "choice": "WAIT", "probability": "0.52"}]})
                    return 200, json.dumps({
                        "candidates": [{"content": {"parts": [{"text": txt}]}}],
                        "usageMetadata": {"promptTokenCount": 50, "candidatesTokenCount": 20},
                    }).encode("utf-8")
                return 200, _gemini_ok_body(in_tokens=70, out_tokens=25)
            if "api.openai.com" in url:
                return 200, _openai_ok_body()
            return 200, b"{}"

        reg = FrontierModelRegistry(
            environ=self._test_secrets(),
            clock=lambda: now_box[0],
            sleep=lambda _s: None,
            http_post=fake_http,
            resolve_dns=lambda _h: None,
            circuit_breaker_config=CircuitBreakerConfig(failure_threshold=2, cooldown_seconds=Decimal("30")),
            retry_policy=RetryPolicy(max_attempts=1),
        )
        # Trip anthropic via claude-fable-5.2
        spec_a1, backend_a1, _ = reg.build_backend("claude-fable-5.2")
        inv_a1 = _make_invocation(backend_a1, spec_a1)
        for _ in range(2):
            with self.assertRaises(FrontierTransportError):
                backend_a1.infer(inv_a1)

        # Sibling anthropic model claude-fable shares provider breaker and fast-fails
        spec_a2, backend_a2, _ = reg.build_backend("claude-fable")
        with self.assertRaises(FrontierCircuitOpenError):
            backend_a2.infer(_make_invocation(backend_a2, spec_a2))

        # OpenAI remains completely isolated & healthy
        spec_oai, backend_oai, _ = reg.build_backend("openai-astra")
        reply_oai = backend_oai.infer(_make_invocation(backend_oai, spec_oai))
        self.assertEqual(reply_oai.generated_tokens, 20)

        # Gemini Decision 1 :decide 404 -> flash 200 does NOT trip gemini_decision breaker
        spec_gd, backend_gd, _ = reg.build_backend("gemini-decision-1")
        reply_gd = backend_gd.infer(_make_invocation(backend_gd, spec_gd))
        self.assertEqual(reply_gd.generated_tokens, 25)

        # Scout also advances clock cleanly via self._clock() and does not trip on :decide 404
        scout_res = reg.scout_opportunities([{"market": "NAS100", "spread_ok": True}])
        self.assertTrue(scout_res["executed"])

        snap = reg.catalog_snapshot()
        self.assertEqual(snap["circuit_breakers"]["anthropic"]["state"], "OPEN")
        self.assertEqual(snap["circuit_breakers"]["openai"]["state"], "CLOSED")
        self.assertEqual(snap["circuit_breakers"]["gemini_decision"]["state"], "CLOSED")
        self.assertEqual(snap["circuit_breakers"]["gemini_decision"]["open_trips"], 0)
        self.assertEqual(snap["circuit_breakers"]["gemini_decision"]["consecutive_failures"], 0)

    def test_bounded_deterministic_retry_and_non_retryable_errors(self) -> None:
        # 1. Retry on 429, 502, TimeoutError -> succeeds on attempt 3
        sleeps_run1: list[float] = []
        sleeps_run2: list[float] = []
        attempts_log: list[dict[str, str]] = []

        def run_sequence(seq: list[object], sleep_sink: list[float]) -> tuple[int, list[dict[str, str]]]:
            idx = [0]
            seen_hdrs: list[dict[str, str]] = []

            def fake_http(url: str, headers: dict, body: bytes, timeout: float, max_bytes: int):
                seen_hdrs.append(dict(headers))
                cur = seq[idx[0]]
                idx[0] += 1
                if isinstance(cur, Exception):
                    raise cur
                if cur == 200:
                    return 200, _anthropic_ok_body()
                return int(cur), b'{"error":"transient"}'

            reg = FrontierModelRegistry(
                environ=self._test_secrets(),
                clock=lambda: T0,
                sleep=sleep_sink.append,
                http_post=fake_http,
                resolve_dns=lambda _h: None,
                retry_policy=RetryPolicy(
                    max_attempts=3,
                    base_delay_seconds=Decimal("0.05"),
                    max_delay_seconds=Decimal("0.20"),
                ),
            )
            spec, backend, verifier = reg.build_backend("claude-fable-5.2")
            inv = _make_invocation(backend, spec)
            reply = backend.infer(inv)
            self.assertTrue(verifier.verify(reply, inv))
            self.assertEqual(reg.catalog_snapshot()["circuit_breakers"]["anthropic"]["state"], "CLOSED")
            return idx[0], seen_hdrs

        cnt1, hdrs1 = run_sequence([429, TimeoutError("read timeout"), 200], sleeps_run1)
        cnt2, _ = run_sequence([502, urllib.error.URLError("dns glitch"), 200], sleeps_run2)
        self.assertEqual(cnt1, 3)
        self.assertEqual(cnt2, 3)
        # Deterministic SHA-256 jitter yields identical sleeps across identical retry policies & invocations
        self.assertEqual(sleeps_run1, sleeps_run2)
        self.assertEqual(len(sleeps_run1), 2)
        for s in sleeps_run1:
            self.assertGreater(s, 0.0)
            self.assertLessEqual(s, 0.20)
        # Every retry attempt still receives valid x-api-key header (never wiped by attempt 1 finally)
        for h in hdrs1:
            self.assertEqual(h["x-api-key"], self._test_secrets()["CAS_FOREX_ANTHROPIC_API_KEY"])

        # 2. Non-retryable errors must fail in strictly 1 attempt with 0 sleeps
        non_retryable_cases = [
            400,
            401,
            403,
            404,
            FrontierTransportError("HTTP redirect 302 refused for outbound AI request", status_code=302, retryable=False),
            FrontierTransportError("frontier AI refused non-public IP for api.anthropic.com", retryable=False),
            FrontierTransportError("frontier AI response exceeded byte limit", retryable=False),
            FrontierConfigurationError("bad config"),
        ]
        for outcome in non_retryable_cases:
            calls_cnt = [0]
            nr_sleeps: list[float] = []

            def nr_http(url: str, headers: dict, body: bytes, timeout: float, max_bytes: int, _o=outcome):
                calls_cnt[0] += 1
                if isinstance(_o, Exception):
                    raise _o
                return int(_o), b'{"error":"bad"}'

            reg = FrontierModelRegistry(
                environ=self._test_secrets(),
                clock=lambda: T0,
                sleep=nr_sleeps.append,
                http_post=nr_http,
                resolve_dns=lambda _h: None,
                retry_policy=RetryPolicy(max_attempts=3),
            )
            spec, backend, _ = reg.build_backend("claude-fable-5.2")
            inv = _make_invocation(backend, spec)
            expected_exc = FrontierConfigurationError if isinstance(outcome, FrontierConfigurationError) else FrontierTransportError
            with self.assertRaises(expected_exc):
                backend.infer(inv)
            self.assertEqual(calls_cnt[0], 1, f"unexpected retry for {outcome!r}")
            self.assertEqual(nr_sleeps, [])

    def test_unsafe_write_never_retried_and_no_venue_import(self) -> None:
        breaker = ProviderCircuitBreaker(clock=lambda: T0)
        policy = RetryPolicy(max_attempts=3, base_delay_seconds=Decimal("0.05"), max_delay_seconds=Decimal("0.20"))
        attempts = [0]
        sleeps: list[float] = []

        def failing_write(_timeout: float) -> None:
            attempts[0] += 1
            raise FrontierTransportError("broker write timeout", status_code=503, retryable=True)

        with self.assertRaises(FrontierTransportError):
            execute_resilient_frontier_call(
                operation_kind=FrontierOperationKind.UNSAFE_WRITE,
                provider="anthropic",
                circuit_breaker=breaker,
                retry_policy=policy,
                clock=lambda: T0,
                sleep=sleeps.append,
                budget_seconds=Decimal("10"),
                idempotency_key="write-1",
                attempt_fn=failing_write,
            )
        self.assertEqual(attempts[0], 1)
        self.assertEqual(sleeps, [])

        # AST check: frontier_backends.py must never import venue/DualShieldBrokerRouter/valve/random
        fb_path = Path(__file__).resolve().parents[2] / "src" / "cas_forex_revamp" / "operator" / "frontier_backends.py"
        fb_src = fb_path.read_text(encoding="utf-8")
        tree = ast.parse(fb_src)
        imported_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module)
            elif isinstance(node, ast.Assert):
                self.fail("runtime assert (Bandit B101) forbidden in frontier_backends.py")
            elif isinstance(node, ast.ExceptHandler) and len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                self.fail("silent except pass (Bandit B110) forbidden in frontier_backends.py")
        for forbidden in ("random", "tks_meta_valve_controller", "dual_shield_router", "venue"):
            self.assertFalse(any(forbidden in mod for mod in imported_modules), f"forbidden import {forbidden}")

    def test_retry_aborts_before_exceeding_call_budget(self) -> None:
        now_box = [T0]
        sleeps: list[float] = []
        attempts = [0]

        def advancing_sleep(sec: float) -> None:
            sleeps.append(sec)
            now_box[0] = now_box[0] + timedelta(seconds=sec)

        def slow_503(url: str, headers: dict, body: bytes, timeout: float, max_bytes: int):
            attempts[0] += 1
            # Simulate HTTP call itself taking 0.96s out of a 1s budget
            now_box[0] = now_box[0] + timedelta(milliseconds=960)
            return 503, b"{}"

        reg = FrontierModelRegistry(
            environ=self._test_secrets(),
            clock=lambda: now_box[0],
            sleep=advancing_sleep,
            http_post=slow_503,
            resolve_dns=lambda _h: None,
            retry_policy=RetryPolicy(max_attempts=3, base_delay_seconds=Decimal("0.10"), max_delay_seconds=Decimal("0.20")),
        )
        spec, backend, _ = reg.build_backend("claude-fable-5.2")
        inv = _make_invocation(backend, spec, max_seconds=1)
        with self.assertRaises(FrontierTransportError):
            backend.infer(inv)
        # Remaining budget (0.04s) <= backoff (~0.05..0.10s), so it aborts after 1 attempt with 0 sleep!
        self.assertEqual(attempts[0], 1)
        self.assertEqual(sleeps, [])
        self.assertLess(now_box[0], T0 + timedelta(seconds=1))

    def test_exact_decimal_micro_usd_spend_metering_across_1000_fractional_calls(self) -> None:
        # Use fractional non-round rates (333_333, 777_777) micro-USD / 1M units across 1,000 calls
        custom_pricing = {
            "deepseek-flash-1017": (333_333, 777_777),
        }

        def ds_http(url: str, headers: dict, body: bytes, timeout: float, max_bytes: int):
            return 200, _openai_ok_body(in_tokens=1, out_tokens=1)

        reg = FrontierModelRegistry(
            environ=self._test_secrets(),
            clock=lambda: T0,
            sleep=lambda _s: None,
            http_post=ds_http,
            resolve_dns=lambda _h: None,
            pricing_micro_usd_per_1m=custom_pricing,
        )
        spec, backend, _ = reg.build_backend("deepseek-flash-1017")
        inv = _make_invocation(backend, spec)

        for _ in range(1000):
            reply = backend.infer(inv)
            # ActualModelDecisionAdapter invariant: reply.input_tokens must match count_input_tokens
            self.assertEqual(reply.input_tokens, backend.count_input_tokens(inv))

        snap = assert_safe_ai_catalog_payload(reg.catalog_snapshot())
        _assert_no_floats(snap)
        # 1000 * (1*333_333 + 1*777_777) = 1_111_110_000 pico-USD = 1111.11 micro-USD = "0.00111111" USD
        expected_pico = 1000 * compute_call_cost_pico_usd(
            "deepseek-flash-1017", input_units=1, output_units=1, pricing_micro_usd_per_1m=custom_pricing
        )
        self.assertEqual(expected_pico, 1_111_110_000)
        self.assertEqual(snap["total_input_units"], 1000)
        self.assertEqual(snap["total_output_units"], 1000)
        self.assertEqual(snap["total_units"], 2000)
        self.assertEqual(snap["total_spend_micro_usd"], pico_usd_to_micro_usd(expected_pico))
        self.assertEqual(snap["total_spend_usd"], pico_usd_to_decimal_text(expected_pico))
        self.assertEqual(snap["total_spend_usd"], "0.00111111")
        # infer() must NOT double-increment calls when AutonomousAiTrader calls record_call()
        ds_entry = next(m for m in snap["models"] if m["model_id"] == "deepseek-flash-1017")
        self.assertEqual(ds_entry["calls"], 0)
        reg.record_call("deepseek-flash-1017", latency_ms=12, status="OK")
        self.assertEqual(reg.catalog_snapshot()["models"][7]["calls"], 1)

    def test_failed_and_ollama_calls_meter_zero_and_adapter_compatible(self) -> None:
        import os
        from hashlib import sha256 as _sha256

        env = dict(self._test_secrets())
        env["CAS_FOREX_OLLAMA_FALLBACK_ENABLED"] = "1"
        fail_flag = [True]
        signer = SupervisedOllamaReceiptSigner(
            algorithm="Ed25519",
            signing_key=bytes(range(1, 33)),
            pid=os.getpid(),
            start_time="unit-start-1",
        )
        binding = SupervisedOllamaBinding(
            pid=os.getpid(),
            start_time="unit-start-1",
            executable_sha256="1" * 64,
            model_manifest_sha256="2" * 64,
            weights_sha256="3" * 64,
            template_sha256="4" * 64,
            tokenizer_sha256="5" * 64,
            endpoint_url="http://127.0.0.1:21434/api/chat",
            auth_secret="sup-auth-" + ("a" * 32),
            receipt_verify_key=signer.public_verify_key(),
            receipt_algorithm="Ed25519",
            process_verifier=lambda _b: True,
            artifact_verifier=lambda _b: True,
            listener_ownership_verifier=lambda _b: True,
        )
        pending_inv_ref: list[tuple[str, str, str]] = []

        def mixed_http(url: str, headers: dict, body: bytes, timeout: float, max_bytes: int):
            if "127.0.0.1" in url:
                sel = {
                    "request_id": "req-adp",
                    "opportunity_set_id": "set-1",
                    "source_state_id": f"state-{STATE_DIGEST}",
                    "selected_action_ref": None,
                    "reason": "ID=0wait_none",
                    "evidence_ids": ["ev-1"],
                }
                sel_json = json.dumps(sel)
                inv_sha, m_id, art_sha = pending_inv_ref[0]
                sup_rcpt = signer.sign_receipt(
                    receipt_id="rcpt-ollama-sup-1",
                    invocation_sha256=inv_sha,
                    model_id=m_id,
                    artifact_sha256=art_sha,
                    response_sha256=_sha256(sel_json.encode("utf-8")).hexdigest(),
                )
                return 200, json.dumps({
                    "message": {"content": sel_json},
                    "prompt_eval_count": 500,
                    "eval_count": 30,
                    "cas_supervisor_receipt": sup_rcpt,
                }).encode("utf-8")
            if fail_flag[0]:
                return 503, b"{}"
            # Provider reports 999 input_tokens != byte-count estimate
            return 200, _anthropic_ok_body(req_id="req-adp", in_tokens=999, out_tokens=25)

        reg = FrontierModelRegistry(
            environ=env,
            clock=lambda: T0,
            sleep=lambda _s: None,
            http_post=mixed_http,
            ollama_http_post=mixed_http,
            resolve_dns=lambda _h: None,
            retry_policy=RetryPolicy(max_attempts=1),
            supervised_ollama=binding,
        )
        # Failed Anthropic call charges 0
        spec_a, backend_a, _ = reg.build_backend("claude-fable-5.2")
        with self.assertRaises(FrontierTransportError):
            backend_a.infer(_make_invocation(backend_a, spec_a, req_id="req-adp"))
        self.assertEqual(reg.catalog_snapshot()["total_spend_micro_usd"], 0)
        self.assertEqual(reg.catalog_snapshot()["total_units"], 0)

        # Ollama fallback call meters units but strictly 0 USD (requires SupervisedOllamaBinding & independent receipt)
        spec_q, backend_q, verifier_q = reg.build_backend("qwen3:0.6b")
        inv_q = _make_invocation(backend_q, spec_q, req_id="req-adp")
        pending_inv_ref.append((content_digest(inv_q), spec_q.model_id, spec_q.artifact_sha256))
        rep_q = backend_q.infer(inv_q)
        self.assertTrue(verifier_q.verify(rep_q, inv_q))
        snap_q = assert_safe_ai_catalog_payload(reg.catalog_snapshot())
        q_item = snap_q["models"][8]
        self.assertEqual(q_item["model_id"], "qwen3:0.6b")
        self.assertEqual(q_item["input_units"], 500)
        self.assertEqual(q_item["output_units"], 30)
        self.assertEqual(q_item["spend_micro_usd"], 0)
        self.assertEqual(q_item["spend_usd"], "0")

        # ActualModelDecisionAdapter.decide() succeeds even when provider input_tokens=999 != _count_bytes_tokens
        fail_flag[0] = False
        _, _, verifier_a = reg.build_backend("claude-fable-5.2")
        adapter = ActualModelDecisionAdapter(
            adapter_id="adapter-resilience",
            model=spec_a,
            backend=backend_a,
            receipt_verifier=verifier_a,
            execution_gate=lambda _inv: None,
            budget=InferenceBudget(
                max_calls=5,
                max_input_tokens_per_call=16000,
                max_generated_tokens_per_call=512,
                max_seconds_per_call=10,
                max_total_seconds=60,
            ),
            clock=lambda: T0,
        )
        scope = RunScope("account", "run", 1, "build", "policy", "scenario", "venue")
        state = StateReference(
            f"state-{STATE_DIGEST}", scope, 1, T0, T0 + timedelta(seconds=60), 1
        )
        intent = ActionIntent(
            "intent-adp",
            scope,
            "decision-adp",
            "set-1",
            "opt-long-eurusd",
            state,
            ActionKind.OPEN,
            "EURUSD",
            DecisionOrigin.ACTUAL_MODEL,
            T0,
            T0 + timedelta(seconds=30),
            quantity=Decimal("1000"),
            side=Side.BUY,
        )
        option = ActionOption(intent.action_ref, "strategy", "H1", "Synthetic option", intent)
        evidence = EvidenceReference("ev-1", EvidenceKind.OBSERVATION, "scenario", "b" * 64, T0)
        fact = DecisionFact("fact-1", "Context", "Synthetic context", (evidence.evidence_id,))
        req = DecisionRequest("req-adp", "set-1", state, (option,), (fact,), (evidence,))
        decision = adapter.decide(req)
        self.assertIsNone(decision.selection.selected_action_ref)
        snap_final = assert_safe_ai_catalog_payload(reg.catalog_snapshot())
        self.assertEqual(snap_final["valve_required"], True)
        self.assertEqual(snap_final["models"][0]["input_units"], 999)
        self.assertEqual(snap_final["models"][0]["output_units"], 25)
        self.assertGreater(snap_final["models"][0]["spend_micro_usd"], 0)

    def test_concurrent_calls_thread_safe(self) -> None:
        counter = [0]
        lock = threading.Lock()

        def concurrent_http(url: str, headers: dict, body: bytes, timeout: float, max_bytes: int):
            with lock:
                counter[0] += 1
                n = counter[0]
            if "generativelanguage.googleapis.com" in url and ":decide" in url:
                return 200, json.dumps({"decisions": [{"market": "NAS100", "choice": "WAIT", "probability": "0.50"}]}).encode("utf-8")
            if n % 5 == 0:
                return 503, b"{}"
            return 200, _anthropic_ok_body(in_tokens=10, out_tokens=5)

        reg = FrontierModelRegistry(
            environ=self._test_secrets(),
            clock=lambda: T0,
            sleep=lambda _s: None,
            http_post=concurrent_http,
            resolve_dns=lambda _h: None,
            circuit_breaker_config=CircuitBreakerConfig(failure_threshold=100, cooldown_seconds=Decimal("30")),
            retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=Decimal("0"), max_delay_seconds=Decimal("0")),
        )
        spec, backend, verifier = reg.build_backend("claude-fable-5.2")

        transient_failures = [0]

        def worker(idx: int) -> None:
            inv = _make_invocation(backend, spec, req_id=f"req-{idx}")
            try:
                rep = backend.infer(inv)
                self.assertTrue(verifier.verify(rep, inv))
            except FrontierTransportError:
                with lock:
                    transient_failures[0] += 1
            if idx % 3 == 0:
                reg.scout_opportunities([{"market": "NAS100"}])
            if idx % 4 == 0:
                ans = reg.answer_explainer_question(question="Status?", context_summary={"execution_mode": "DEMO"})
                self.assertTrue(ans["read_only"])
            reg.catalog_snapshot()

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(worker, i) for i in range(40)]
            for f in futures:
                f.result(timeout=10.0)

        snap = assert_safe_ai_catalog_payload(reg.catalog_snapshot())
        _assert_no_floats(snap)
        self.assertGreater(snap["total_input_units"], 0)
        self.assertGreater(snap["total_spend_micro_usd"], 0)

    def test_zero_secrets_logged_or_leaked_in_errors_repr_and_snapshots(self) -> None:
        secrets_map = self._test_secrets()
        secret_values = list(secrets_map.values())
        outcomes = [401, 429, 503, FrontierTransportError("HTTP redirect 302 refused", status_code=302, retryable=False), b"not-json"]
        step = [0]

        def hostile_http(url: str, headers: dict, body: bytes, timeout: float, max_bytes: int):
            cur = outcomes[min(step[0], len(outcomes) - 1)]
            step[0] += 1
            if isinstance(cur, Exception):
                raise cur
            if isinstance(cur, bytes):
                return 200, cur
            return int(cur), b'{"error":"denied"}'

        log_records: list[str] = []

        class _MemHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                log_records.append(self.format(record))

        root_logger = logging.getLogger()
        handler = _MemHandler()
        root_logger.addHandler(handler)
        try:
            reg = FrontierModelRegistry(
                environ=secrets_map,
                clock=lambda: T0,
                sleep=lambda _s: None,
                http_post=hostile_http,
                resolve_dns=lambda _h: None,
                circuit_breaker_config=CircuitBreakerConfig(failure_threshold=2, cooldown_seconds=Decimal("30")),
                retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=Decimal("0"), max_delay_seconds=Decimal("0")),
            )
            spec, backend, _ = reg.build_backend("claude-fable-5.2")
            inv = _make_invocation(backend, spec)

            captured_texts: list[str] = [repr(reg), repr(backend)]
            for _ in range(len(outcomes) + 2):
                try:
                    backend.infer(inv)
                except Exception as exc:
                    captured_texts.append(str(exc))
                    captured_texts.append(repr(exc))

            ans = reg.answer_explainer_question(question="Why paused?", context_summary={"execution_mode": "DEMO"})
            snap = assert_safe_ai_catalog_payload(reg.catalog_snapshot())
            captured_texts.append(json.dumps(ans))
            captured_texts.append(json.dumps(snap))
            captured_texts.extend(log_records)

            combined = "\n".join(captured_texts)
            for secret_val in secret_values:
                self.assertNotIn(secret_val, combined)
        finally:
            root_logger.removeHandler(handler)

    def test_explainer_neon_fallback_and_tts_use_resilient_retry_and_breaker(self) -> None:
        calls: list[str] = []
        seen_reqs: list[tuple[str, dict, float]] = []
        mode = ["neon_flaky_once"]

        def fake_http(url: str, headers: dict, body: bytes, timeout: float, max_bytes: int):
            calls.append(url)
            seen_reqs.append((url, json.loads(body.decode("utf-8")), timeout))
            if mode[0] == "neon_flaky_once":
                if len(calls) == 1:
                    return 503, b'{"error":"transient"}'
                return 200, json.dumps({
                    "candidates": [{"content": {"parts": [{"text": json.dumps({"spoken_question": "", "answer": "Neon recovered after retry."})}]}}]
                }).encode("utf-8")
            if mode[0] == "gemini_down_anthropic_up":
                if "generativelanguage.googleapis.com" in url:
                    return 503, b'{"error":"gemini down"}'
                return 200, json.dumps({
                    "content": [{"type": "text", "text": json.dumps({"answer": "Secondary Claude fallback succeeded."})}],
                    "usage": {"input_tokens": 40, "output_tokens": 12},
                }).encode("utf-8")
            if mode[0] == "tts_flaky_once":
                if len(calls) == 1:
                    return 503, b'{"error":"tts busy"}'
                return 200, json.dumps({
                    "candidates": [{"content": {"parts": [{"inlineData": {"mimeType": "audio/L16;codec=pcm;rate=24000", "data": "AAAA"}}]}}]
                }).encode("utf-8")
            return 500, b"{}"

        reg = FrontierModelRegistry(
            environ={
                "CAS_FOREX_ANTHROPIC_API_KEY": self._test_secrets()["CAS_FOREX_ANTHROPIC_API_KEY"],
                "CAS_FOREX_GEMINI_API_KEY": self._test_secrets()["CAS_FOREX_GEMINI_API_KEY"],
            },
            clock=lambda: T0,
            sleep=lambda _s: None,
            http_post=fake_http,
            resolve_dns=lambda _h: None,
            circuit_breaker_config=CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=Decimal("30")),
            retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=Decimal("0"), max_delay_seconds=Decimal("0")),
        )
        ans1 = reg.answer_explainer_question("Status?", context_summary={"execution_mode": "DEMO"})
        self.assertEqual(ans1["answer"], "Neon recovered after retry.")
        self.assertEqual(len(calls), 2)
        self.assertEqual(seen_reqs[0][1]["generationConfig"].get("thinkingConfig"), {"thinkingLevel": "LOW"})
        self.assertEqual(seen_reqs[0][2], 25.0)

        calls.clear()
        mode[0] = "tts_flaky_once"
        tts1 = reg.synthesize_explainer_speech("Hello owner", voice_name="Kore")
        self.assertTrue(tts1["ok"])
        self.assertEqual(len(calls), 2)

        # Trip Gemini circuit on Neon failure -> secondary Claude fallback answers cleanly (no NameError)
        calls.clear()
        mode[0] = "gemini_down_anthropic_up"
        ans2 = reg.answer_explainer_question("Fallback check?", context_summary={"execution_mode": "DEMO"})
        self.assertEqual(ans2["model_id"], "claude-fable-5.2")
        self.assertEqual(ans2["answer"], "Secondary Claude fallback succeeded.")
        self.assertEqual(reg.catalog_snapshot()["circuit_breakers"]["gemini"]["state"], "OPEN")

    def test_malformed_usage_counts_and_non_finite_decision_probabilities_and_scout_breaker_order(self) -> None:
        from cas_forex_revamp.operator.frontier_backends import (
            _extract_gemini_decision_selection,
            _extract_provider_text_and_usage,
        )

        # 1. Malformed output token counts across all 4 providers fall back cleanly (no TypeError/ValueError)
        secrets = self._test_secrets()
        reg_tmp = FrontierModelRegistry(
            environ={"CAS_FOREX_ANTHROPIC_API_KEY": secrets["CAS_FOREX_ANTHROPIC_API_KEY"]},
            clock=lambda: T0,
            http_post=lambda *_a: (200, b"{}"),
            resolve_dns=lambda _h: None,
        )
        spec_tmp, backend_tmp, _ = reg_tmp.build_backend("claude-fable-5.2")
        inv = _make_invocation(backend_tmp, spec_tmp, req_id="req-usage-guard")
        sel_text = json.dumps({
            "request_id": "req-usage-guard",
            "opportunity_set_id": "set-1",
            "source_state_id": f"state-{STATE_DIGEST}",
            "selected_action_ref": None,
            "reason": "ID=0wait_none",
            "evidence_ids": ["ev-1"],
        })
        for provider, doc in (
            ("anthropic", {"content": [{"type": "text", "text": sel_text}], "usage": {"output_tokens": None}}),
            ("gemini", {"candidates": [{"content": {"parts": [{"text": sel_text}]}}], "usageMetadata": {"candidatesTokenCount": "bad"}}),
            ("openai", {"choices": [{"message": {"content": sel_text}}], "usage": {"completion_tokens": -5}}),
            ("deepseek", {"choices": [{"message": {"content": sel_text}}], "usage": {"completion_tokens": True}}),
            ("ollama", {"message": {"content": sel_text}, "eval_count": None}),
        ):
            out_txt, out_tok, _ = _extract_provider_text_and_usage(
                provider, doc, inv, min_probability=Decimal("0.60")
            )
            self.assertIn("req-usage-guard", out_txt)
            self.assertGreaterEqual(out_tok, 1)

        # 2. Non-finite probability in Gemini Decision-1 & CAS_FOREX_DECISION_MIN_PROBABILITY="NaN"
        for bad_prob in ("NaN", "Infinity", "-Infinity", None):
            _, _, parsed_p = _extract_gemini_decision_selection(
                {"decisions": [{"choice": "opt-long-eurusd", "probability": bad_prob}]},
                inv,
                min_probability=Decimal("0.60"),
            )
            self.assertEqual(parsed_p, Decimal("0.50"))

        with self.assertRaises(FrontierConfigurationError):
            FrontierModelRegistry(
                environ={"CAS_FOREX_DECISION_MIN_PROBABILITY": "NaN"},
                clock=lambda: T0,
                http_post=lambda *_a: (200, b"{}"),
                resolve_dns=lambda _h: None,
            )

        # 3. scout_opportunities handles probability="NaN" and trips breaker BEFORE record_success on bad payload
        scout_mode = ["nan_prob"]

        def scout_http(_url: str, _hdrs: dict[str, str], _body: bytes, _timeout: float, _max_bytes: int) -> tuple[int, bytes]:
            if scout_mode[0] == "nan_prob":
                return 200, json.dumps({"decisions": [{"market": "EURUSD", "choice": "BUY", "probability": "NaN"}]}).encode("utf-8")
            return 200, json.dumps({"decisions": "not-a-list"}).encode("utf-8")

        reg = FrontierModelRegistry(
            environ={"CAS_FOREX_GEMINI_API_KEY": secrets["CAS_FOREX_GEMINI_API_KEY"]},
            clock=lambda: T0,
            sleep=lambda _s: None,
            http_post=scout_http,
            resolve_dns=lambda _h: None,
            circuit_breaker_config=CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=Decimal("30")),
            retry_policy=RetryPolicy(max_attempts=1, base_delay_seconds=Decimal("0"), max_delay_seconds=Decimal("0")),
        )
        s1 = reg.scout_opportunities([{"market": "EURUSD", "choices": ["BUY"]}])
        self.assertEqual(s1["decisions"][0]["probability"], "0.5")
        self.assertEqual(reg.catalog_snapshot()["circuit_breakers"]["gemini_decision"]["state"], "CLOSED")

        scout_mode[0] = "bad_payload"
        with self.assertRaises(FrontierTransportError):
            reg.scout_opportunities([{"market": "EURUSD", "choices": ["BUY"]}])
        self.assertEqual(reg.catalog_snapshot()["circuit_breakers"]["gemini_decision"]["state"], "OPEN")


if __name__ == "__main__":
    unittest.main()
