"""Source-authored negative controls. All transports/process observations are FAKE.

NOT_RUN. These tests, even when passing, cannot establish an actual model run.
"""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from cas_forex_revamp.contracts import ContractError, canonical_bytes, content_digest
from cas_forex_revamp.operator.model_evidence import ModelEvidenceStore
from cas_forex_revamp.operator.ollama_backend import ChatHttpResponse
from cas_forex_revamp.operator.preflight_http import ScopedLoopbackClient
from cas_forex_revamp.operator.runtime_observer import LinuxRuntimeObserver, PinnedFile, SupervisorSpec, process_stat
from cas_forex_revamp.operator.stage_b import StageBModelPorts
from cas_forex_revamp.operator.token_preflight import rendered_text, token_ids, tokenizer_identity
from test_operator import T0
from test_ollama_backend import Fixture, ROOT
from test_loopback_http import FakeSocket, wire


class FakeRuntime(LinuxRuntimeObserver):
    """Test data only. Never use this class as an actual-model evidence source."""
    def __init__(self, pin):
        self.exited = self.changed = False
        files = {role: {"sha256": digest, "path": "/fake/" + role, "bytes": 1, "device": 1, "inode": n, "mtime_ns": 1}
                 for n, (role, digest) in enumerate((("ollama", "e"*64), ("runner", "f"*64),
                     ("weight", pin.model.artifact_sha256), ("template", pin.template_sha256),
                     ("manifest", pin.manifest_sha256), ("parameters", "1"*64),
                     ("config", "2"*64), ("license", "3"*64)), 1)}
        self.bound = {"server": {"pid": 100, "start_ticks": 1},
            "runner": {"pid": 101, "port": 20001, "mapped_model": files["weight"], "argv": ["fake-test-runner"]},
            "last_bound_runner": None, "lifecycle": "MAPPED", "files": files}
    def prepare(self):
        return deepcopy({"server": self.bound["server"], "files": self.bound["files"]})
    def capture(self, *, allow_exited=False):
        value = deepcopy(self.bound)
        if self.changed:
            value["runner"]["pid"] = 999
        if self.exited:
            if not allow_exited:
                raise ContractError("fake runner exited")
            value["last_bound_runner"], value["runner"] = value["runner"], None
            value["lifecycle"] = "EXITED_AFTER_RESPONSE"
        return value
    def require_same(self, expected):
        actual = self.capture()
        if actual != expected:
            raise ContractError("fake runtime changed")
        return actual


class Pipeline:
    def __init__(self, directory):
        self.f = Fixture()
        self.runtime = FakeRuntime(self.f.pin)
        self.pin = replace(self.f.pin, tokenizer_sha256=tokenizer_identity(self.runtime.bound["files"]))
        self.store = ModelEvidenceStore(Path(directory) / "test.model-evidence.sqlite3", run_id="fixture-run", deadline=T0+timedelta(minutes=30))
        self.store.initialize(create=True)
        self.ports = StageBModelPorts(store=self.store, phase="probe", runtime=self.runtime,
            clock=lambda: self.f.now, execution_gate=lambda invocation: None)
        self.posts = []
        self.render = {"model": self.pin.model.model_id, "created_at": "2026-10-10T20:00:00Z",
                       "message": {"role": "", "content": ""}, "done": False,
                       "_debug_info": {"rendered_template": "FAKE rendered input <|im_end|>"}}
        self.tokens = list(range(100))
        self.http_error = None
        self.ports.preflight.client_factory = lambda operation, port: self
        self.ports._client = self
        self.backend = self.ports.backend(pin=self.pin,
            selection_schema_bytes=(ROOT / "docs/contracts/decision-selection.schema.json").read_bytes(),
            max_calls=2, max_total_seconds=60)
    def post(self, request):
        self.posts.append(request)
        data = json.loads(request.body)
        if "_debug_render_only" in data:
            result = self.render
        elif request.endpoint.endswith("/tokenize"):
            result = {"tokens": self.tokens}
        else:
            if self.http_error:
                raise self.http_error
            result = self.f.payload
        return ChatHttpResponse(200, "application/json", canonical_bytes(result))
    def run(self):
        self.backend.count_input_tokens(self.f.invocation)
        return self.backend.infer(self.f.invocation)


class StageBTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.p = Pipeline(self.directory.name)

    def test_preflight_calls_render_and_tokenize_but_no_generation(self):
        p = self.p
        self.assertEqual(p.backend.count_input_tokens(p.f.invocation), 100)
        self.assertEqual(len(p.posts), 2)
        render, tokenize = [json.loads(r.body) for r in p.posts]
        original = json.loads(p.backend._request(p.f.invocation).body)
        self.assertEqual(render, {**original, "_debug_render_only": True, "keep_alive": 30})
        self.assertEqual(tokenize, {"content": p.render["_debug_info"]["rendered_template"],
                                   "add_special": True, "parse_special": True, "with_pieces": False})
        self.assertEqual(p.backend.attempted_calls, 0)
        self.assertFalse(any(r["payload"].get("operation") == "generation" for r in p.store.records()))

    def test_fake_roundtrip_retains_requested_and_observed_fields_separately(self):
        p = self.p
        reply = p.run()
        self.assertTrue(p.ports.verify(reply, p.f.invocation))
        record = p.store.resolve(reply.receipt_id)["payload"]
        self.assertEqual(record["requested_input_ceiling"], 4096)
        self.assertEqual(record["preflight_input_tokens"], 100)
        self.assertEqual(record["observed_provider_input_tokens"], 100)
        self.assertEqual(record["observed_provider_generated_tokens"], 20)
        self.assertIsNone(record["observed_internal_sampling_settings"])
        self.assertEqual(json.loads(p.posts[-1].body)["keep_alive"], 0)

    def test_input_mismatch_retained_before_rejection_and_no_free_retry(self):
        p = self.p
        p.f.payload["prompt_eval_count"] = 99
        with self.assertRaises(ContractError):
            p.run()
        saved = p.store.resolve("generation-http-"+content_digest(p.f.invocation))
        self.assertEqual(saved["kind"], "MODEL_HTTP_RESPONSE")
        self.assertEqual(p.backend.attempted_calls, 1)
        with self.assertRaises(Exception):
            p.backend.infer(p.f.invocation)
        self.assertEqual(len(p.posts), 3)

    def test_runtime_change_after_preflight_prevents_generation(self):
        p = self.p
        p.backend.count_input_tokens(p.f.invocation)
        p.runtime.changed = True
        with self.assertRaises(ContractError):
            p.backend.infer(p.f.invocation)
        self.assertEqual(len(p.posts), 2)

    def test_runner_exit_before_generation_is_not_after_response(self):
        p = self.p
        p.backend.count_input_tokens(p.f.invocation)
        p.runtime.exited = True
        with self.assertRaises(ContractError):
            p.backend.infer(p.f.invocation)
        self.assertEqual(len(p.posts), 2)

    def test_runner_exit_after_response_preserves_prior_mapping_as_prior(self):
        p = self.p
        original_post = p.post
        class ExitClient:
            def post(self, request):
                result = original_post(request)
                p.runtime.exited = True
                return result
        p.ports._client = ExitClient()
        reply = p.run()
        self.assertTrue(p.ports.verify(reply, p.f.invocation))
        observation = p.store.resolve("runtime-after-"+content_digest(p.f.invocation))["payload"]["runtime"]
        self.assertIsNone(observation["runner"])
        self.assertEqual(observation["lifecycle"], "EXITED_AFTER_RESPONSE")
        self.assertEqual(observation["last_bound_runner"]["pid"], 101)

    def test_generation_error_is_durably_spent(self):
        p = self.p
        p.http_error = TimeoutError("fake timeout")
        with self.assertRaises(TimeoutError):
            p.run()
        key = content_digest(p.f.invocation)
        self.assertEqual(p.store.resolve("generation-attempt-"+key)["kind"], "MODEL_HTTP_ATTEMPT")
        self.assertEqual(p.store.resolve("generation-error-"+key)["payload"]["error_type"], "TimeoutError")

    def test_forged_reply_count_text_or_artifact_is_rejected(self):
        p = self.p
        reply = p.run()
        for altered in (replace(reply, input_tokens=99), replace(reply, generated_tokens=21),
                        replace(reply, raw_selection_json="{}"),
                        replace(reply, model=replace(reply.model, artifact_sha256="0"*64))):
            with self.subTest(altered=altered), self.assertRaises(ContractError):
                p.ports.verify(altered, p.f.invocation)

    def test_render_generation_or_images_are_rejected(self):
        p = self.p
        for changes in ({"eval_count": 1}, {"done": True}, {"message": {"role": "assistant", "content": "x"}},
                        {"_debug_info": {"rendered_template": "x", "image_count": 1}}):
            response = ChatHttpResponse(200, "application/json", canonical_bytes({**p.render, **changes}))
            with self.subTest(changes=changes), self.assertRaises(ContractError):
                rendered_text(response, p.pin.model.model_id)

    def test_boolean_negative_or_oversized_token_ids_are_rejected(self):
        for tokens in ([True], [-1], [2147483648], [], [1]*8193):
            with self.subTest(length=len(tokens)), self.assertRaises(ContractError):
                token_ids(ChatHttpResponse(200, "application/json", canonical_bytes({"tokens": tokens})))

    def test_input_ceiling_rejects_before_generation(self):
        p = self.p
        p.tokens = list(range(4097))
        with self.assertRaises(ContractError):
            p.run()
        self.assertEqual(len(p.posts), 2)
        self.assertEqual(p.backend.attempted_calls, 0)

    def test_wrong_tokenizer_pin_prevents_even_render(self):
        p = self.p
        with self.assertRaises(ContractError):
            p.ports.preflight.count(p.f.invocation, p.backend._request(p.f.invocation), replace(p.pin, tokenizer_sha256="0"*64))
        self.assertEqual(p.posts, [])

    def test_revoked_gate_prevents_any_preflight_transport(self):
        p = self.p
        def denied(invocation):
            raise ContractError("fake revoked gate")
        p.ports.exchange.gate = denied
        with self.assertRaises(ContractError):
            p.run()
        self.assertEqual(p.posts, [])

    def test_checkpoint_restore_preserves_failed_attempt_and_phase_budgets(self):
        p = self.p
        p.http_error = TimeoutError()
        with self.assertRaises(TimeoutError):
            p.run()
        checkpoint = p.store.checkpoint()
        reopened = ModelEvidenceStore(p.store.path, run_id=p.store.run_id, deadline=p.store.deadline)
        reopened.initialize(expected_checkpoint=checkpoint)
        self.assertEqual(reopened.checkpoint(), checkpoint)
        with self.assertRaises(ContractError):
            reopened.begin_http(phase="acceptance", operation="generation", invocation_sha256=content_digest(p.f.invocation),
                body_sha256="a"*64, timeout_seconds=30, now=T0)

    def test_restore_without_retained_checkpoint_is_rejected(self):
        with self.assertRaises(ContractError):
            self.p.store.initialize()

    def test_wrong_run_deadline_or_checkpoint_is_rejected(self):
        p = self.p
        checkpoint = p.store.checkpoint()
        for store in (ModelEvidenceStore(p.store.path, run_id="different-run", deadline=p.store.deadline),
                      ModelEvidenceStore(p.store.path, run_id=p.store.run_id, deadline=p.store.deadline+timedelta(seconds=1))):
            with self.assertRaises(ContractError):
                store.initialize(expected_checkpoint=checkpoint)
        with self.assertRaises(ContractError):
            p.store.initialize(expected_checkpoint=(1, "0"*64))

    def test_probe_call_cap_is_shared_across_store_instances(self):
        p = self.p
        for n in (1, 2):
            p.store.begin_http(phase="probe", operation="generation", invocation_sha256=str(n)*64,
                body_sha256="a"*64, timeout_seconds=30, now=T0)
        other = ModelEvidenceStore(p.store.path, run_id=p.store.run_id, deadline=p.store.deadline)
        other.initialize(expected_checkpoint=p.store.checkpoint())
        with self.assertRaises(ContractError):
            other.begin_http(phase="probe", operation="generation", invocation_sha256="3"*64,
                body_sha256="a"*64, timeout_seconds=30, now=T0)

    def test_phase_absolute_deadline_and_unknown_phase_fail_closed(self):
        p = self.p
        for phase, now in (("u1", T0), ("probe", p.store.deadline-timedelta(seconds=1))):
            with self.subTest(phase=phase), self.assertRaises(ContractError):
                p.store.begin_http(phase=phase, operation="generation", invocation_sha256="4"*64,
                    body_sha256="a"*64, timeout_seconds=30, now=now)

    def test_receipt_conflict_cannot_rewrite_history(self):
        p = self.p
        p.store.append("receipt-1", "TEST_FIXTURE", {"value": 1}, now=T0)
        with self.assertRaises(ContractError):
            p.store.append("receipt-1", "TEST_FIXTURE", {"value": 2}, now=T0)
        self.assertEqual(p.store.resolve("receipt-1")["payload"], {"value": 1})


class SupervisorAndTransportTests(unittest.TestCase):
    def test_proc_stat_handles_spaces_and_parentheses_and_detects_exit(self):
        fields = ["S", "100"] + ["0"]*17 + ["54321"]
        self.assertEqual(process_stat("101 (name with (parens)) "+" ".join(fields)), (100, 54321))
        fields[0] = "Z"
        with self.assertRaises(ContractError):
            process_stat("101 (dead) "+" ".join(fields))

    def test_unsafe_paths_and_duplicate_missing_pin_roles_rejected(self):
        for name in ("relative", "/tmp/../model", "/tmp//model", "//other/model"):
            with self.subTest(name=name), self.assertRaises(ContractError):
                PinnedFile("weight", name, 1, "a"*64)
        with self.assertRaises(ContractError):
            SupervisorSpec(100, 1, (PinnedFile("weight", "/model", 1, "a"*64),)*8)
        with self.assertRaises(ContractError):
            SupervisorSpec(100, 1, (None,)*8)

    def test_scoped_tokenizer_endpoint_rejects_redirected_port_before_socket(self):
        client = ScopedLoopbackClient(operation="tokenize", port=20001)
        with patch("cas_forex_revamp.operator.preflight_http.socket.socket") as sock:
            with self.assertRaises(ContractError):
                client.post(wire(endpoint="http://127.0.0.1:20002/tokenize"))
            sock.assert_not_called()

    def test_scoped_tokenizer_uses_exact_supplied_loopback_port(self):
        sock = FakeSocket(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
        with patch("cas_forex_revamp.operator.preflight_http.socket.socket", return_value=sock), \
             patch("cas_forex_revamp.operator.preflight_http.select.select", side_effect=lambda r,w,x,t:(r,w,[])):
            result = ScopedLoopbackClient(operation="tokenize", port=20001).post(wire(endpoint="http://127.0.0.1:20001/tokenize"))
        self.assertEqual(result.body, b"{}")
        self.assertEqual(sock.address, ("127.0.0.1", 20001))
        self.assertIn(b"POST /tokenize HTTP/1.1", sock.sent)
        self.assertTrue(sock.closed)
