"""Inert Stage B composition ports with independently retained wire/process evidence.

Only explicit backend calls do work. This module never starts Ollama, approves a
route, dispatches an action or labels fake data as execution evidence. Trust rests
on the approved frozen source/runtime and supervisor, not on a journal self-hash.
"""
from __future__ import annotations
from dataclasses import replace
from datetime import datetime, timedelta
from hashlib import sha256
from cas_forex_revamp.contracts import ContractError, canonical_bytes, content_digest
from cas_forex_revamp.contracts.primitives import utc_time
from .model_evidence import ModelEvidenceStore, PHASE_LIMITS
from .ollama_backend import ENDPOINT, OllamaChatBackend, RuntimeObservation, _decode
from .runtime_observer import LinuxRuntimeObserver
from .token_preflight import (EvidenceExchange, RenderTokenPreflight, decode_response,
                              response_wire, tokenizer_identity)
from .preflight_http import ScopedLoopbackClient


def _stamp(value):
    return utc_time(datetime.fromisoformat(value.replace("Z", "+00:00")), "receipt time")


class StageBModelPorts:
    """One serial backend per instance; durable store shared by approved phases.

    Pass this object as ActualModelDecisionAdapter.receipt_verifier. The caller
    supplies the same execution gate/clock to the adapter and OperatorSession.
    Store initialization and process launch belong to the explicit guest driver.
    """
    def __init__(self, *, store: ModelEvidenceStore, phase: str,
                 runtime: LinuxRuntimeObserver, clock, execution_gate):
        if not isinstance(store, ModelEvidenceStore) or not isinstance(runtime, LinuxRuntimeObserver):
            raise ContractError("explicit durable evidence store and Linux supervisor required")
        if phase not in PHASE_LIMITS or not callable(clock) or not callable(execution_gate):
            raise ContractError("approved phase, clock and execution gate required")
        self.store, self.phase, self.runtime = store, phase, runtime
        self.clock, self.gate = clock, execution_gate
        self.exchange = EvidenceExchange(store, phase=phase, clock=clock, execution_gate=execution_gate)
        self.preflight = RenderTokenPreflight(exchange=self.exchange, runtime=runtime, clock=clock)
        self._backend = self._pin = self._active = None
        self._deadlines = {}
        self._client = ScopedLoopbackClient()

    def backend(self, *, pin, selection_schema_bytes: bytes, max_calls: int, max_total_seconds: int):
        calls, seconds = PHASE_LIMITS[self.phase]
        if self._backend is not None or max_calls > calls or max_total_seconds > seconds:
            raise ContractError("one backend and bounded phase allowance required")
        backend = OllamaChatBackend(endpoint=ENDPOINT, client=self, pin=pin,
            selection_schema_bytes=selection_schema_bytes, clock=self.clock,
            token_counter=self.count, token_verifier=self.preflight.verify,
            runtime_observer=self.observe_runtime, runtime_verifier=self.verify_runtime,
            recorder=self.record, execution_gate=self.gate, absolute_deadline=self.store.deadline,
            max_calls=max_calls, max_total_seconds=max_total_seconds)
        self._backend, self._pin = backend, pin
        return backend

    def count(self, invocation, request, pin):
        key = content_digest(invocation)
        if key in self._deadlines:
            raise ContractError("preflight is one-shot")
        deadline = min(self.store.deadline, utc_time(self.clock(), "clock") +
                       timedelta(seconds=invocation.budget.max_seconds_per_call))
        self._deadlines[key] = deadline
        return self.preflight.count(invocation, replace(request, absolute_deadline=deadline), pin)

    def _token(self, invocation):
        record = self.store.resolve("token-proof-" + content_digest(invocation))
        if record["kind"] != "MODEL_TOKEN_PREFLIGHT":
            raise ContractError("missing source token proof")
        return record["payload"]

    def observe_runtime(self, invocation, request, pin):
        key = content_digest(invocation)
        token = self._token(invocation)
        generation_id = "generation-http-" + key
        has_response = any(r["receipt_id"] == generation_id and r["kind"] == "MODEL_HTTP_RESPONSE"
                           for r in self.store.records())
        stage = "after" if has_response else "before"
        observed = self.runtime.capture(allow_exited=has_response)
        expected = token["runtime"]
        runner = observed["runner"] if observed["lifecycle"] == "MAPPED" else observed["last_bound_runner"]
        if (observed["server"] != expected["server"] or observed["files"] != expected["files"]
                or runner != expected["runner"] or (not has_response and observed["lifecycle"] != "MAPPED")):
            raise ContractError("runtime no longer binds the exact preflight model/process")
        now = utc_time(self.clock(), "clock")
        until = min(self._deadlines[key], now + timedelta(seconds=30))
        result = RuntimeObservation("runtime-" + stage + "-" + key, key, sha256(request.body).hexdigest(),
                                    content_digest(pin), now, until)
        self.store.append(result.receipt_id, "MODEL_RUNTIME_OBSERVATION", {
            "observation": result, "stage": stage, "runtime": observed,
            "token_proof_id": "token-proof-" + key,
            "response_id": generation_id if has_response else None,
        }, now=now)
        if not has_response:
            self._active = (invocation, request)
        return result

    def verify_runtime(self, observation, invocation, request, pin):
        record = self.store.resolve(observation.receipt_id)
        payload = record["payload"]
        if record["kind"] != "MODEL_RUNTIME_OBSERVATION" or canonical_bytes(payload["observation"]) != canonical_bytes(observation):
            raise ContractError("runtime observation differs from its controlled source")
        token = self._token(invocation)
        actual = payload["runtime"]
        expected = token["runtime"]
        if actual["lifecycle"] not in {"MAPPED", "EXITED_AFTER_RESPONSE"}:
            raise ContractError("unknown runner lifecycle")
        bound = actual["runner"] if actual["lifecycle"] == "MAPPED" else actual["last_bound_runner"]
        if (actual["server"] != expected["server"] or actual["files"] != expected["files"]
                or bound != expected["runner"] or tokenizer_identity(actual["files"]) != pin.tokenizer_sha256
                or (observation.invocation_sha256, observation.body_sha256, observation.pin_sha256) !=
                   (content_digest(invocation), sha256(request.body).hexdigest(), content_digest(pin))):
            raise ContractError("runtime source does not bind the requested artifact/input")
        if payload["stage"] == "before":
            if actual["lifecycle"] != "MAPPED" or payload["response_id"] is not None:
                raise ContractError("before-inference mapping is unavailable")
        elif payload["stage"] == "after":
            response = self.store.resolve(payload["response_id"])
            if response["kind"] != "MODEL_HTTP_RESPONSE" or response["payload"]["operation"] != "generation" or response["payload"]["invocation_sha256"] != content_digest(invocation):
                raise ContractError("after-inference lifecycle lacks independent response")
        else:
            raise ContractError("unknown runtime observation stage")
        return True

    def post(self, request):
        if self._active is None:
            raise ContractError("generation has no independently observed preflight binding")
        invocation, expected = self._active
        self._active = None
        if request != expected or request.endpoint != ENDPOINT:
            raise ContractError("generation transport changed the exact observed request")
        self.runtime.require_same(self._token(invocation)["runtime"])
        bounded = replace(request, absolute_deadline=min(request.absolute_deadline,
                           self._deadlines[content_digest(invocation)]))
        response, _ = self.exchange.post(invocation, bounded, operation="generation", client=self._client)
        return response

    def record(self, observation):
        invocation = observation.invocation
        key = content_digest(invocation)
        source = self.store.resolve("generation-http-" + key)
        wire = source["payload"]
        if (source["kind"] != "MODEL_HTTP_RESPONSE" or wire["operation"] != "generation"
                or wire["request"]["body_utf8"] != observation.request.body.decode()
                or wire["response"] != response_wire(observation.response)):
            raise ContractError("backend reply differs from independently captured HTTP bytes")
        self.preflight.verify(observation.token_proof, invocation, observation.request, self._pin)
        for runtime in (observation.runtime_before, observation.runtime_after):
            self.verify_runtime(runtime, invocation, observation.request, self._pin)
        before = self.store.resolve(observation.runtime_before.receipt_id)["payload"]["runtime"]
        data = _decode(observation.response.body, 65536)
        receipt_id = "inference-" + key
        self.store.append(receipt_id, "MODEL_INFERENCE_RECEIPT", {
            "invocation_sha256": key, "request_sha256": invocation.request_sha256,
            "invocation": invocation, "pin": self._pin,
            "generation_http_id": source["receipt_id"], "token_proof_id": observation.token_proof.receipt_id,
            "runtime_before_id": observation.runtime_before.receipt_id,
            "runtime_after_id": observation.runtime_after.receipt_id,
            "requested_model": invocation.model, "observed_provider_model": data["model"],
            "observed_mapped_weight_sha256": before["runner"]["mapped_model"]["sha256"],
            "requested_input_ceiling": invocation.budget.max_input_tokens_per_call,
            "requested_generated_ceiling": invocation.budget.max_generated_tokens_per_call,
            "preflight_input_tokens": observation.token_proof.input_tokens,
            "observed_provider_input_tokens": data["prompt_eval_count"],
            "observed_provider_generated_tokens": data["eval_count"],
            "requested_options": _decode(observation.request.body, 1114112)["options"],
            "observed_runner_argv": before["runner"]["argv"],
            "observed_internal_sampling_settings": None,
            "raw_selection_json": observation.raw_selection_json,
            "started_at": observation.started_at, "completed_at": observation.completed_at,
        }, now=self.clock())
        return receipt_id

    def verify(self, reply, invocation):
        """Re-resolve durable wire and supervisor records; a reply self-hash is insufficient."""
        source = self.store.resolve(reply.receipt_id)
        p = source["payload"]
        key = content_digest(invocation)
        if (source["kind"] != "MODEL_INFERENCE_RECEIPT" or p["invocation_sha256"] != key
                or reply.invocation_sha256 != key or canonical_bytes(p["invocation"]) != canonical_bytes(invocation)
                or canonical_bytes(p["pin"]) != canonical_bytes(self._pin)
                or reply.model != invocation.model or p["request_sha256"] != invocation.request_sha256):
            raise ContractError("inference receipt does not bind the exact invocation")
        wire_record = self.store.resolve(p["generation_http_id"])
        wire = wire_record["payload"]
        response = decode_response(wire_record)
        token = self._token(invocation)
        if (wire_record["kind"] != "MODEL_HTTP_RESPONSE" or wire["operation"] != "generation"
                or wire["invocation_sha256"] != key or wire["request"]["endpoint"] != ENDPOINT
                or wire["request"]["body_sha256"] != token["body_sha256"]
                or sha256(wire["request"]["body_utf8"].encode()).hexdigest() != token["body_sha256"]):
            raise ContractError("inference source wire differs from preflight")
        # Reuse strict pinned protocol parsing, but resolve the proof independently.
        from .ollama_backend import ChatHttpRequest, ExactTokenProof
        request = ChatHttpRequest(ENDPOINT, wire["request"]["body_utf8"].encode(),
            wire["request"]["timeout_seconds"], 65536, _stamp(wire["request"]["absolute_deadline"]))
        proof = ExactTokenProof(p["token_proof_id"], key, token["body_sha256"], token["pin_sha256"],
            token["rendered_prompt_sha256"], token["tokenizer_sha256"], token["input_tokens"])
        self.preflight.verify(proof, invocation, request, self._pin)
        text, inputs, outputs = self._backend._response(response, invocation, proof)
        for field in ("runtime_before_id", "runtime_after_id"):
            raw = self.store.resolve(p[field])["payload"]["observation"]
            runtime = RuntimeObservation(raw["receipt_id"], raw["invocation_sha256"], raw["body_sha256"],
                raw["pin_sha256"], _stamp(raw["observed_at"]), _stamp(raw["valid_until"]))
            self.verify_runtime(runtime, invocation, request, self._pin)
        if (text != reply.raw_selection_json or text != p["raw_selection_json"]
                or (inputs, outputs) != (reply.input_tokens, reply.generated_tokens)
                or (inputs, outputs) != (p["observed_provider_input_tokens"], p["observed_provider_generated_tokens"])
                or inputs != p["preflight_input_tokens"]
                or p["observed_mapped_weight_sha256"] != invocation.model.artifact_sha256
                or p["observed_provider_model"] != invocation.model.model_id
                or (_stamp(p["started_at"]), _stamp(p["completed_at"])) != (reply.started_at, reply.completed_at)
                or not reply.started_at <= _stamp(wire["started_at"]) <= _stamp(wire["completed_at"]) <= reply.completed_at
                or reply.completed_at > _stamp(wire["request"]["absolute_deadline"])):
            raise ContractError("inference reply differs from independent output/usage/artifact evidence")
        return True
