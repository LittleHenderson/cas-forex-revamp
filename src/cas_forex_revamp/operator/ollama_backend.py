"""Concrete Ollama chat wire backend with injected bounded transport and evidence.

Import/construction performs no I/O. No installed Ollama package, environment,
credentials, service discovery, retry, fallback, or execution authority is used.
Independent exact tokenizer/runtime/receipt implementations are required ports;
this module does not pretend their absence is successful actual-model evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from hashlib import sha256
import json
from threading import Lock
from typing import Callable, Protocol

from cas_forex_revamp.contracts import ContractError, canonical_bytes, content_digest
from cas_forex_revamp.contracts.decisions import DecisionSelection
from cas_forex_revamp.contracts.primitives import digest, identifier, integer, utc_time
from .decisions import OperatorUnavailable
from .model import InferenceReply, ModelInvocation, ModelSpecification

OLLAMA_VERSION = "0.40.2"
OLLAMA_ARCHIVE_SHA256 = "726bee78706c281b0eeef00746efe51a044d71c592c3f0b195820707f31fdf04"
ENDPOINT = "http://127.0.0.1:11434/api/chat"


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ContractError("duplicate Ollama JSON key")
        value[key] = item
    return value


def _constant(value):
    raise ContractError("nonfinite Ollama JSON value")


def _decode(raw, maximum):
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise ContractError("Ollama JSON body outside byte bound")
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ContractError("invalid Ollama JSON") from exc
    if type(result) is not dict:
        raise ContractError("Ollama JSON object required")
    return result


@dataclass(frozen=True, slots=True)
class OllamaRuntimePin:
    version: str
    archive_sha256: str
    model: ModelSpecification
    manifest_sha256: str
    template_sha256: str
    tokenizer_sha256: str
    selection_schema_sha256: str
    context_tokens: int = 8192
    threads: int = 2

    def __post_init__(self):
        if self.version != OLLAMA_VERSION or self.archive_sha256 != OLLAMA_ARCHIVE_SHA256:
            raise ContractError("unreviewed Ollama runtime release")
        for key in ("archive_sha256", "manifest_sha256", "template_sha256", "tokenizer_sha256", "selection_schema_sha256"):
            digest(getattr(self, key), key)
        if not isinstance(self.model, ModelSpecification) or self.model.reasoning_effort != "disabled":
            raise ContractError("this pin requires explicit think=false model policy")
        if self.model.model_id != "qwen3:0.6b":
            raise ContractError("unreviewed model name for this backend")
        integer(self.context_tokens, "context_tokens", minimum=1)
        integer(self.threads, "threads", minimum=1)
        if self.context_tokens > 8192 or self.threads > 2:
            raise ContractError("pin exceeds the source-prepared CPU/context ceiling")


@dataclass(frozen=True, slots=True)
class ChatHttpRequest:
    endpoint: str
    body: bytes
    timeout_seconds: int
    response_byte_limit: int
    absolute_deadline: datetime


@dataclass(frozen=True, slots=True)
class ChatHttpResponse:
    status: int
    content_type: str
    body: bytes


class BoundedChatClient(Protocol):
    def post(self, request: ChatHttpRequest) -> ChatHttpResponse:
        """One direct loopback POST. Enforce total deadline incl headers/read,
        response cap before allocation, no proxies/redirects/retries/credentials.
        External process supervisor must enforce deadline if runtime hangs.
        """
        ...


@dataclass(frozen=True, slots=True)
class ExactTokenProof:
    receipt_id: str
    invocation_sha256: str
    body_sha256: str
    pin_sha256: str
    rendered_prompt_sha256: str
    tokenizer_sha256: str
    input_tokens: int

    def __post_init__(self):
        identifier(self.receipt_id, "token_receipt_id")
        for key in ("invocation_sha256", "body_sha256", "pin_sha256", "rendered_prompt_sha256", "tokenizer_sha256"):
            digest(getattr(self, key), key)
        integer(self.input_tokens, "exact_input_tokens", minimum=1)


@dataclass(frozen=True, slots=True)
class RuntimeObservation:
    receipt_id: str
    invocation_sha256: str
    body_sha256: str
    pin_sha256: str
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        identifier(self.receipt_id, "runtime_receipt_id")
        for key in ("invocation_sha256", "body_sha256", "pin_sha256"):
            digest(getattr(self, key), key)
        utc_time(self.observed_at, "observed_at")
        utc_time(self.valid_until, "valid_until")
        if self.valid_until <= self.observed_at:
            raise ContractError("runtime observation lifetime is empty")


@dataclass(frozen=True, slots=True)
class ChatObservation:
    invocation: ModelInvocation
    request: ChatHttpRequest
    response: ChatHttpResponse
    token_proof: ExactTokenProof
    runtime_before: RuntimeObservation
    runtime_after: RuntimeObservation
    raw_selection_json: str
    started_at: datetime
    completed_at: datetime
    input_tokens: int
    generated_tokens: int


@dataclass(frozen=True, slots=True)
class BackendAttempt:
    invocation_sha256: str
    body_sha256: str
    status: str
    error_type: str | None
    receipt_id: str | None


class OllamaChatBackend:
    """Bounded one-shot implementation of ModelBackend.

    Token counter is strictly inference-free. Its independent verifier must resolve
    exact template/BOS/EOS/special-token behavior, not trust a supplied integer.
    Runtime verifier must check loaded artifact/template/settings against pin,
    including migration drift. Recorder must append independent observation bytes;
    ActualModelDecisionAdapter still verifies its returned receipt separately.
    None of these callbacks has a default that accepts absent evidence.
    """

    def __init__(self, *, endpoint: str, client: BoundedChatClient, pin: OllamaRuntimePin,
                 selection_schema_bytes: bytes, clock: Callable[[], datetime],
                 token_counter: Callable[[ModelInvocation, ChatHttpRequest, OllamaRuntimePin], ExactTokenProof],
                 token_verifier: Callable[[ExactTokenProof, ModelInvocation, ChatHttpRequest, OllamaRuntimePin], bool],
                 runtime_observer: Callable[[ModelInvocation, ChatHttpRequest, OllamaRuntimePin], RuntimeObservation],
                 runtime_verifier: Callable[[RuntimeObservation, ModelInvocation, ChatHttpRequest, OllamaRuntimePin], bool],
                 recorder: Callable[[ChatObservation], str],
                 execution_gate: Callable[[ModelInvocation], None],
                 absolute_deadline: datetime, max_calls: int, max_total_seconds: int):
        if endpoint != ENDPOINT or not isinstance(pin, OllamaRuntimePin):
            raise ContractError("only the explicitly supplied pinned loopback endpoint is supported")
        utc_time(absolute_deadline, "absolute_deadline")
        integer(max_calls, "max_calls", minimum=1)
        integer(max_total_seconds, "max_total_seconds", minimum=1)
        if max_calls > 32 or max_total_seconds > 5400:
            raise ContractError("backend exceeds the shared acceptance ceiling")
        if sha256(selection_schema_bytes).hexdigest() != pin.selection_schema_sha256:
            raise ContractError("selection schema bytes differ from trusted pin")
        schema = _decode(selection_schema_bytes, 65536)
        if schema.get("$id") != "urn:cas-forex:decision-selection:1.0":
            raise ContractError("unsupported selection schema identity")
        for callback in (clock, token_counter, token_verifier, runtime_observer, runtime_verifier, recorder, execution_gate):
            if not callable(callback):
                raise ContractError("all independent evidence and gate callbacks are required")
        if not callable(getattr(client, "post", None)):
            raise ContractError("explicit bounded HTTP client required")
        self._endpoint, self._client, self._pin, self._schema = endpoint, client, pin, schema
        self._clock, self._counter, self._token_verifier = clock, token_counter, token_verifier
        self._runtime_observer, self._runtime_verifier = runtime_observer, runtime_verifier
        self._recorder, self._gate, self._deadline = recorder, execution_gate, absolute_deadline
        self._max_calls, self._max_seconds = max_calls, max_total_seconds
        self._proofs = {}
        self._used = set()
        self._calls = self._reserved_seconds = 0
        self._attempts = []
        self._lock = Lock()

    @property
    def attempts(self):
        return tuple(self._attempts)

    @property
    def attempted_calls(self):
        return self._calls

    def _request(self, invocation):
        if not isinstance(invocation, ModelInvocation) or invocation.model != self._pin.model:
            raise ContractError("invocation differs from pinned model policy")
        if invocation.seed is None or invocation.seed > 2147483647:
            raise ContractError("a fixed bounded seed is required")
        budget = invocation.budget
        if budget.max_input_tokens_per_call + budget.max_generated_tokens_per_call > self._pin.context_tokens:
            raise ContractError("budget does not reserve the full input and output context")
        body = canonical_bytes({"model": self._pin.model.model_id,
            "messages": [{"role": "system", "content": invocation.system_policy},
                         {"role": "user", "content": invocation.packet_json}],
            "stream": False, "think": False, "truncate": False, "shift": False,
            "keep_alive": 0, "format": self._schema,
            "options": {"seed": invocation.seed, "temperature": 0, "num_gpu": 0,
                "num_thread": self._pin.threads, "num_ctx": self._pin.context_tokens,
                "num_predict": budget.max_generated_tokens_per_call, "num_batch": 128,
                "top_k": 1, "top_p": 1, "min_p": 0, "repeat_penalty": 1, "use_mmap": True}})
        if len(body) > 1114112:
            raise ContractError("encoded chat request exceeds byte bound")
        return ChatHttpRequest(self._endpoint, body, budget.max_seconds_per_call, 65536, self._deadline)

    def _available(self, invocation):
        now = utc_time(self._clock(), "clock")
        duration = invocation.budget.max_seconds_per_call
        if (self._calls >= self._max_calls or self._reserved_seconds + duration > self._max_seconds
                or (self._deadline - now).total_seconds() < duration):
            raise OperatorUnavailable("backend call/time/deadline budget exhausted")
        self._gate(invocation)
        return now

    def _check_proof(self, proof, invocation, request):
        if not isinstance(proof, ExactTokenProof) or (
            proof.invocation_sha256, proof.body_sha256, proof.pin_sha256, proof.tokenizer_sha256
        ) != (content_digest(invocation), sha256(request.body).hexdigest(), content_digest(self._pin), self._pin.tokenizer_sha256):
            raise ContractError("token proof does not bind the exact request and runtime")
        if proof.input_tokens > invocation.budget.max_input_tokens_per_call:
            raise OperatorUnavailable("exact token count exceeds input ceiling")
        if self._token_verifier(proof, invocation, request, self._pin) is not True:
            raise ContractError("independent exact token verification failed")

    def count_input_tokens(self, invocation):
        with self._lock:
            self._available(invocation)
            request = self._request(invocation)
            key = content_digest(invocation)
            if key in self._used:
                raise OperatorUnavailable("invocation already attempted; retries disabled")
            if key not in self._proofs:
                if len(self._proofs) >= self._max_calls:
                    raise OperatorUnavailable("pending token proof limit reached")
                proof = self._counter(invocation, request, self._pin)
                self._check_proof(proof, invocation, request)
                self._proofs[key] = proof
            self._check_proof(self._proofs[key], invocation, request)
            return self._proofs[key].input_tokens

    def _runtime(self, invocation, request):
        observation = self._runtime_observer(invocation, request, self._pin)
        now = utc_time(self._clock(), "clock")
        if not isinstance(observation, RuntimeObservation) or (
            observation.invocation_sha256, observation.body_sha256, observation.pin_sha256
        ) != (content_digest(invocation), sha256(request.body).hexdigest(), content_digest(self._pin)):
            raise ContractError("runtime observation differs from exact invocation/pin")
        if not observation.observed_at <= now < observation.valid_until:
            raise ContractError("runtime observation is stale")
        if self._runtime_verifier(observation, invocation, request, self._pin) is not True:
            raise ContractError("independent loaded runtime verification failed")
        return observation

    def infer(self, invocation):
        with self._lock:
            started = self._available(invocation)
            request = replace(self._request(invocation), absolute_deadline=min(
                self._deadline, started + timedelta(seconds=invocation.budget.max_seconds_per_call)))
            key, body_hash = content_digest(invocation), sha256(request.body).hexdigest()
            if key in self._used or key not in self._proofs:
                raise OperatorUnavailable("exact pre-count is required and invocation is one-shot")
            proof = self._proofs[key]
            self._check_proof(proof, invocation, request)
            before = self._runtime(invocation, request)
            self._available(invocation)  # Recheck expiry/approval after verification latency.
            self._used.add(key)
            del self._proofs[key]
            self._calls += 1
            self._reserved_seconds += request.timeout_seconds
            try:
                response = self._client.post(request)
                completed = utc_time(self._clock(), "clock")
                if not started <= completed <= self._deadline or (completed - started).total_seconds() > request.timeout_seconds:
                    raise OperatorUnavailable("transport exceeded total call deadline")
                text, inputs, outputs = self._response(response, invocation, proof)
                after = self._runtime(invocation, request)
                self._gate(invocation)  # Revoked execution cannot become an accepted reply.
                observation = ChatObservation(invocation, request, response, proof, before, after,
                                              text, started, completed, inputs, outputs)
                receipt = identifier(self._recorder(observation), "independent_inference_receipt_id")
                finished = utc_time(self._clock(), "clock")
                if not started <= finished <= self._deadline or (finished - started).total_seconds() > request.timeout_seconds:
                    raise OperatorUnavailable("evidence handling exceeded the total deadline")
                reply = InferenceReply(text, receipt, key, self._pin.model, started, completed, inputs, outputs)
                self._attempts.append(BackendAttempt(key, body_hash, "OBSERVED_UNVERIFIED", None, receipt))
                return reply
            except Exception as exc:
                self._attempts.append(BackendAttempt(key, body_hash, "FAILED_OR_UNKNOWN", type(exc).__name__, None))
                raise

    def _response(self, response, invocation, proof):
        if not isinstance(response, ChatHttpResponse) or type(response.status) is not int or response.status != 200:
            raise ContractError("Ollama returned no successful direct response")
        if type(response.content_type) is not str or response.content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise ContractError("nonstreaming JSON content type required")
        data = _decode(response.body, 65536)
        allowed = {"model", "created_at", "message", "done", "done_reason", "total_duration",
                   "load_duration", "prompt_eval_count", "prompt_eval_cached_count", "prompt_eval_duration",
                   "eval_count", "eval_duration"}
        required = {"model", "created_at", "message", "done", "done_reason", "prompt_eval_count", "eval_count"}
        if data.keys() - allowed or required - data.keys():
            raise ContractError("unexpected or missing pinned Ollama response fields")
        if data["model"] != self._pin.model.model_id or data["done"] is not True or data["done_reason"] != "stop":
            raise ContractError("wrong model or incomplete/length-limited response")
        stamp = data["created_at"]
        if type(stamp) is not str or not stamp.endswith("Z"):
            raise ContractError("Ollama created_at requires UTC Z")
        try:
            utc_time(datetime.fromisoformat(stamp[:-1] + "+00:00"), "created_at")
        except ValueError as exc:
            raise ContractError("invalid Ollama timestamp") from exc
        for name in (allowed - {"model", "created_at", "message", "done", "done_reason"}) & data.keys():
            integer(data[name], name)
        inputs, outputs = data["prompt_eval_count"], data["eval_count"]
        if inputs != proof.input_tokens or not 1 <= outputs <= invocation.budget.max_generated_tokens_per_call:
            raise ContractError("observed token usage differs from exact proof or output budget")
        message = data["message"]
        if type(message) is not dict or message.keys() - {"role", "content", "thinking"} or message.get("role") != "assistant":
            raise ContractError("tools/nonassistant/unknown message fields are forbidden")
        if message.get("thinking", "") != "":
            raise ContractError("private reasoning output violates disabled thinking policy")
        text = message.get("content")
        if type(text) is not str:
            raise ContractError("selection text is absent")
        try:
            selected = _decode(text.encode("utf-8"), 16384)
        except UnicodeError as exc:
            raise ContractError("selection text is invalid UTF-8") from exc
        fields = {"request_id", "opportunity_set_id", "source_state_id", "selected_action_ref", "reason", "evidence_ids"}
        if set(selected) != fields or type(selected["evidence_ids"]) is not list:
            raise ContractError("selection must contain only the exact six public fields")
        # Shape/byte/ID checks here; outer adapter binds to the actual supplied request.
        DecisionSelection(selected["request_id"], selected["opportunity_set_id"], selected["source_state_id"],
                          selected["selected_action_ref"], selected["reason"], tuple(selected["evidence_ids"]))
        return text, inputs, outputs
