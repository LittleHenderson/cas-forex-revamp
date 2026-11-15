"""Fake-transport negative controls; no actual-model evidence. NOT_RUN."""
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
import json
from pathlib import Path
import unittest

from cas_forex_revamp.contracts import ContractError, InferenceBudget, canonical_bytes, content_digest
from cas_forex_revamp.operator.decisions import OperatorUnavailable
from cas_forex_revamp.operator.model import ModelInvocation, ModelSpecification, SYSTEM_POLICY
from cas_forex_revamp.operator.ollama_backend import (
    ENDPOINT, OLLAMA_ARCHIVE_SHA256, OLLAMA_VERSION, ChatHttpResponse, ExactTokenProof,
    OllamaChatBackend, OllamaRuntimePin, RuntimeObservation,
)
from test_operator import T0, request, selection

ROOT = Path(__file__).resolve().parents[2]


class Fixture:
    """All callbacks are deliberate fakes, never production receipt authorities."""
    def __init__(self, *, max_calls=2):
        self.now = T0
        schema = (ROOT / "docs/contracts/decision-selection.schema.json").read_bytes()
        self.model = ModelSpecification("qwen3:0.6b", "a" * 64, "disabled", "fixture-v1")
        self.pin = OllamaRuntimePin(OLLAMA_VERSION, OLLAMA_ARCHIVE_SHA256, self.model,
                                   "b" * 64, "c" * 64, "d" * 64, sha256(schema).hexdigest())
        self.invocation = ModelInvocation(content_digest(request()), self.model, "session-1", SYSTEM_POLICY,
                                         canonical_bytes(request()).decode(), InferenceBudget(2, 4096, 256, 30, 60), seed=42)
        self.posts = []
        self.records = []
        self.counter_calls = 0
        self.tokens_valid = self.runtime_valid = True
        self.delay = 0
        self.status = 200
        self.content_type = "application/json"
        self.error = None
        self.payload = {"model": "qwen3:0.6b", "created_at": "2026-10-10T20:00:00Z",
                        "message": {"role": "assistant", "content": canonical_bytes(selection(request())).decode()},
                        "done": True, "done_reason": "stop", "prompt_eval_count": 100, "eval_count": 20}
        self.raw_override = None
        self.backend = OllamaChatBackend(endpoint=ENDPOINT, client=self, pin=self.pin,
            selection_schema_bytes=schema, clock=lambda: self.now, token_counter=self.counter,
            token_verifier=lambda *args: self.tokens_valid, runtime_observer=self.runtime,
            runtime_verifier=lambda *args: self.runtime_valid, recorder=self.record,
            execution_gate=lambda invocation: None, absolute_deadline=T0 + timedelta(seconds=90),
            max_calls=max_calls, max_total_seconds=60)

    def counter(self, invocation, wire, pin):
        self.counter_calls += 1
        return ExactTokenProof("fake-token", content_digest(invocation), sha256(wire.body).hexdigest(),
                               content_digest(pin), "e" * 64, pin.tokenizer_sha256, 100)

    def runtime(self, invocation, wire, pin):
        return RuntimeObservation("fake-runtime", content_digest(invocation), sha256(wire.body).hexdigest(),
                                  content_digest(pin), self.now, self.now + timedelta(seconds=60))

    def record(self, observation):
        self.records.append(observation)
        return "fake-unverified-inference"

    def post(self, wire):
        self.posts.append(wire)
        self.now += timedelta(seconds=self.delay)
        if self.error:
            raise self.error
        return ChatHttpResponse(self.status, self.content_type,
                                self.raw_override if self.raw_override is not None else canonical_bytes(self.payload))

    def run(self):
        self.backend.count_input_tokens(self.invocation)
        return self.backend.infer(self.invocation)


class OllamaBackendTests(unittest.TestCase):
    def test_construction_and_precount_do_not_call_transport(self):
        f = Fixture()
        self.assertEqual(f.posts, [])
        self.assertEqual(f.backend.count_input_tokens(f.invocation), 100)
        self.assertEqual(f.backend.count_input_tokens(f.invocation), 100)
        self.assertEqual(f.counter_calls, 1)
        self.assertEqual(f.posts, [])

    def test_fixed_wire_and_observed_unverified_receipt(self):
        f = Fixture()
        reply = f.run()
        wire = f.posts[0]
        body = json.loads(wire.body)
        self.assertEqual(wire.endpoint, ENDPOINT)
        self.assertIs(body["stream"], False)
        self.assertIs(body["think"], False)
        self.assertIs(body["truncate"], False)
        self.assertIs(body["shift"], False)
        self.assertNotIn("tools", body)
        self.assertEqual(body["options"]["seed"], 42)
        self.assertEqual(body["options"]["num_gpu"], 0)
        self.assertEqual(body["options"]["num_predict"], 256)
        self.assertEqual(len(body["messages"]), 2)
        self.assertEqual(reply.input_tokens, 100)
        self.assertEqual(len(f.records), 1)
        self.assertEqual(f.backend.attempts[0].status, "OBSERVED_UNVERIFIED")

    def test_wait_is_accepted_as_explicit_null_only(self):
        f = Fixture()
        f.payload["message"]["content"] = canonical_bytes(selection(request(), wait=True)).decode()
        self.assertIsNone(json.loads(f.run().raw_selection_json)["selected_action_ref"])

    def test_missing_precount_fails_before_http(self):
        f = Fixture()
        with self.assertRaises(OperatorUnavailable):
            f.backend.infer(f.invocation)
        self.assertEqual(f.posts, [])

    def test_independent_token_and_runtime_failures_prevent_http(self):
        for field in ("tokens_valid", "runtime_valid"):
            f = Fixture()
            setattr(f, field, False)
            with self.subTest(field=field), self.assertRaises(ContractError):
                f.run()
            self.assertEqual(f.posts, [])

    def test_wrong_token_body_binding_prevents_http(self):
        f = Fixture()
        real = f.backend._counter
        f.backend._counter = lambda *args: replace(real(*args), body_sha256="0" * 64)
        with self.assertRaises(ContractError):
            f.run()
        self.assertEqual(f.posts, [])

    def test_no_retry_after_timeout_or_success(self):
        for error in (None, TimeoutError("fake")):
            f = Fixture()
            f.error = error
            if error:
                with self.assertRaises(TimeoutError):
                    f.run()
            else:
                f.run()
            with self.assertRaises(OperatorUnavailable):
                f.backend.infer(f.invocation)
            self.assertEqual(len(f.posts), 1)
            self.assertEqual(f.backend.attempted_calls, 1)

    def test_missing_usage_bool_usage_and_wrong_count_rejected(self):
        for change in ({"prompt_eval_count": True}, {"prompt_eval_count": 101}, {"eval_count": 257}, {"eval_count": 0}):
            f = Fixture()
            f.payload.update(change)
            with self.subTest(change=change), self.assertRaises(ContractError):
                f.run()
            self.assertEqual(f.records, [])
        f = Fixture()
        del f.payload["prompt_eval_count"]
        with self.assertRaises(ContractError):
            f.run()

    def test_remote_model_and_incomplete_or_length_reply_rejected(self):
        for change in ({"remote_host": "elsewhere"}, {"model": "other"}, {"done": False}, {"done_reason": "length"}):
            f = Fixture()
            f.payload.update(change)
            with self.subTest(change=change), self.assertRaises(ContractError):
                f.run()

    def test_tools_thinking_and_extra_action_fields_rejected(self):
        for change in ({"tool_calls": []}, {"thinking": "private"}, {"role": "tool"}):
            f = Fixture()
            f.payload["message"].update(change)
            with self.subTest(change=change), self.assertRaises(ContractError):
                f.run()
        f = Fixture()
        selected = json.loads(f.payload["message"]["content"])
        selected["quantity"] = "1000000"
        f.payload["message"]["content"] = json.dumps(selected)
        with self.assertRaises(ContractError):
            f.run()

    def test_duplicate_and_oversize_and_bad_http_fail_without_retry(self):
        for raw in (b'{"done":true,"done":true}', b"x" * 65537, b"\xff"):
            f = Fixture()
            f.raw_override = raw
            with self.assertRaises(ContractError):
                f.run()
            self.assertEqual(len(f.posts), 1)
        for status in (302, 500):
            f = Fixture()
            f.status = status
            with self.assertRaises(ContractError):
                f.run()

    def test_wall_time_and_global_deadline_fail_closed(self):
        f = Fixture()
        f.delay = 31
        with self.assertRaises(OperatorUnavailable):
            f.run()
        self.assertEqual(f.records, [])
        f = Fixture()
        f.now += timedelta(seconds=61)
        with self.assertRaises(OperatorUnavailable):
            f.run()
        self.assertEqual(f.posts, [])

    def test_shared_budget_blocks_second_arm(self):
        f = Fixture(max_calls=1)
        f.run()
        with self.assertRaises(OperatorUnavailable):
            f.backend.count_input_tokens(replace(f.invocation, session_id="other-arm"))
        self.assertEqual(len(f.posts), 1)

    def test_missing_seed_and_context_overflow_prevent_http(self):
        f = Fixture()
        for inv in (replace(f.invocation, seed=None), replace(f.invocation, budget=InferenceBudget(2, 8192, 256, 30, 60))):
            with self.assertRaises(ContractError):
                f.backend.count_input_tokens(inv)
        self.assertEqual(f.posts, [])
