"""Observed HTTP exchange and pinned non-generating render/tokenize preflight."""
from __future__ import annotations
from base64 import b64encode, b64decode
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
import json
from cas_forex_revamp.contracts import ContractError, canonical_bytes, content_digest
from cas_forex_revamp.contracts.primitives import utc_time
from .ollama_backend import ChatHttpRequest, ChatHttpResponse, ExactTokenProof, ENDPOINT, _decode
from .preflight_http import ScopedLoopbackClient

TOKEN_POLICY = {"ollama": "0.40.2", "runner_build": "b11351", "text_only": True,
                "architecture": "qwen3", "add_special": True, "parse_special": True,
                "with_pieces": False, "inspected_add_bos_token": False}


def tokenizer_identity(files):
    return content_digest({"policy": TOKEN_POLICY,
        "ollama_sha256": files["ollama"]["sha256"], "runner_sha256": files["runner"]["sha256"],
        "weight_sha256": files["weight"]["sha256"]})


def response_wire(response):
    if not isinstance(response, ChatHttpResponse):
        raise ContractError("typed HTTP response required")
    return {"status": response.status, "content_type": response.content_type,
            "body_base64": b64encode(response.body).decode("ascii"), "body_sha256": sha256(response.body).hexdigest()}


def decode_response(record):
    data = record["payload"]["response"]
    try:
        raw = b64decode(data["body_base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ContractError("malformed recorded HTTP bytes") from exc
    if sha256(raw).hexdigest() != data["body_sha256"]:
        raise ContractError("recorded HTTP bytes changed")
    return ChatHttpResponse(data["status"], data["content_type"], raw)


class EvidenceExchange:
    """Records the actual injected transport boundary, independent of model claims."""
    def __init__(self, store, *, phase, clock, execution_gate):
        self.store, self.phase, self.clock, self.gate = store, phase, clock, execution_gate

    def post(self, invocation, request, *, operation, client):
        self.gate(invocation)
        start = utc_time(self.clock(), "clock")
        invocation_hash = content_digest(invocation)
        attempt = self.store.begin_http(phase=self.phase, operation=operation,
            invocation_sha256=invocation_hash, body_sha256=sha256(request.body).hexdigest(),
            timeout_seconds=request.timeout_seconds, now=start)
        receipt_id = operation + "-http-" + invocation_hash
        try:
            response = client.post(request)
            end = utc_time(self.clock(), "clock")
            # Record observations before backend parsing, including rejected output.
            self.store.append(receipt_id, "MODEL_HTTP_RESPONSE", {
                "attempt_id": attempt["receipt_id"], "operation": operation,
                "invocation_sha256": invocation_hash,
                "request": {"endpoint": request.endpoint, "body_utf8": request.body.decode("utf-8"),
                            "body_sha256": sha256(request.body).hexdigest(),
                            "timeout_seconds": request.timeout_seconds,
                            "absolute_deadline": request.absolute_deadline},
                "response": response_wire(response), "started_at": start, "completed_at": end,
            }, now=end)
            if not start <= end <= request.absolute_deadline or (end - start).total_seconds() > request.timeout_seconds:
                raise TimeoutError("observed HTTP exchange exceeded deadline")
            return response, receipt_id
        except Exception as exc:
            end = utc_time(self.clock(), "clock")
            if end < self.store.deadline:
                self.store.append(operation + "-error-" + invocation_hash, "MODEL_HTTP_ERROR",
                    {"attempt_id": attempt["receipt_id"], "error_type": type(exc).__name__}, now=end)
            raise


def _json_response(response, maximum):
    if response.status != 200 or response.content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise ContractError("non-generating endpoint did not return bounded JSON success")
    return _decode(response.body, maximum)


def rendered_text(response, model_id):
    value = _json_response(response, 1114112)
    allowed = {"model", "created_at", "message", "done", "done_reason", "_debug_info",
               "total_duration", "load_duration", "prompt_eval_count", "prompt_eval_cached_count",
               "prompt_eval_duration", "eval_count", "eval_duration"}
    if value.keys() - allowed or value.get("model") != model_id or value.get("done") is not False:
        raise ContractError("render response is not the pinned non-generating form")
    if any(type(value.get(k, 0)) is not int or value.get(k, 0) != 0 for k in ("prompt_eval_count", "prompt_eval_cached_count", "eval_count")):
        raise ContractError("render-only request unexpectedly evaluated/generated tokens")
    message = value.get("message")
    if type(message) is not dict or message != {"role": "", "content": ""}:
        raise ContractError("render response contains an unexpected assistant output")
    info = value.get("_debug_info")
    if type(info) is not dict or info.keys() - {"rendered_template", "image_count"} or "rendered_template" not in info or type(info.get("image_count", 0)) is not int or info.get("image_count", 0) != 0:
        raise ContractError("text-only render receipt required")
    text = info["rendered_template"]
    if type(text) is not str or not text or len(text.encode("utf-8")) > 1048576:
        raise ContractError("rendered template exceeds bound or is missing")
    return text


def token_ids(response):
    value = _json_response(response, 131072)
    tokens = value.get("tokens")
    if set(value) != {"tokens"} or type(tokens) is not list or not 1 <= len(tokens) <= 8192:
        raise ContractError("bounded token ID array required")
    if any(type(x) is not int or not 0 <= x <= 2147483647 for x in tokens):
        raise ContractError("invalid tokenizer output ID")
    return tokens


class RenderTokenPreflight:
    """No generation request. The existing backend separately spends inference."""
    def __init__(self, *, exchange, runtime, clock, client_factory=None):
        self.exchange, self.runtime, self.clock = exchange, runtime, clock
        self.client_factory = client_factory or (lambda operation, port: ScopedLoopbackClient(operation=operation, port=port))

    def count(self, invocation, request, pin):
        if request.endpoint != ENDPOINT:
            raise ContractError("preflight accepts only the actual pinned chat request")
        original = _decode(request.body, 1114112)
        if (original.get("model") != pin.model.model_id or original.get("think") is not False
                or original.get("truncate") is not False or original.get("shift") is not False
                or original.get("stream") is not False or "tools" in original or "_debug_render_only" in original):
            raise ContractError("unsafe or unsupported original request for preflight")
        # Bind the new helper to unchanged exact supplied input, not a shortened copy.
        if original.get("messages") != [{"role": "system", "content": invocation.system_policy},
                                        {"role": "user", "content": invocation.packet_json}]:
            raise ContractError("preflight request changed exact model input")
        prepared = self.runtime.prepare()
        if tokenizer_identity(prepared["files"]) != pin.tokenizer_sha256:
            raise ContractError("tokenizer identity differs from independently hashed runtime/model")
        for role, expected in (("weight", pin.model.artifact_sha256), ("manifest", pin.manifest_sha256), ("template", pin.template_sha256)):
            if prepared["files"][role]["sha256"] != expected:
                raise ContractError("staged model identity differs from requested pin")
        start = utc_time(self.clock(), "clock")
        deadline = min(request.absolute_deadline, start + timedelta(seconds=request.timeout_seconds))
        render_body = {**original, "_debug_render_only": True, "keep_alive": 30}
        render_request = replace(request, body=canonical_bytes(render_body), response_byte_limit=1114112, absolute_deadline=deadline)
        rendered, render_id = self.exchange.post(invocation, render_request, operation="render",
            client=self.client_factory("chat", 11434))
        prompt = rendered_text(rendered, pin.model.model_id)
        bound = self.runtime.capture()
        if bound["server"] != prepared["server"] or bound["files"] != prepared["files"]:
            raise ContractError("runtime changed while rendering")
        port = bound["runner"]["port"]
        body = canonical_bytes({"content": prompt, "add_special": True, "parse_special": True, "with_pieces": False})
        tokenize_request = ChatHttpRequest(f"http://127.0.0.1:{port}/tokenize", body,
            request.timeout_seconds, 131072, deadline)
        self.runtime.require_same(bound)
        response, token_id = self.exchange.post(invocation, tokenize_request, operation="tokenize",
            client=self.client_factory("tokenize", port))
        tokens = token_ids(response)
        after = self.runtime.require_same(bound)
        if len(tokens) > invocation.budget.max_input_tokens_per_call or len(tokens) + invocation.budget.max_generated_tokens_per_call > pin.context_tokens:
            raise ContractError("observed preflight count exceeds approved input/context ceiling")
        payload = {"invocation_sha256": content_digest(invocation), "body_sha256": sha256(request.body).hexdigest(),
            "pin_sha256": content_digest(pin), "tokenizer_sha256": pin.tokenizer_sha256,
            "rendered_prompt_sha256": sha256(prompt.encode("utf-8")).hexdigest(),
            "input_tokens": len(tokens), "token_ids": tokens, "policy": TOKEN_POLICY,
            "render_http_id": render_id, "tokenize_http_id": token_id, "runtime": after,
            "requested_input_ceiling": invocation.budget.max_input_tokens_per_call,
            "requested_generated_ceiling": invocation.budget.max_generated_tokens_per_call,
            "observed_provider_input_tokens": None, "observed_provider_generated_tokens": None}
        receipt_id = "token-proof-" + content_digest(invocation)
        self.exchange.store.append(receipt_id, "MODEL_TOKEN_PREFLIGHT", payload, now=self.clock())
        return ExactTokenProof(receipt_id, payload["invocation_sha256"], payload["body_sha256"], payload["pin_sha256"],
                               payload["rendered_prompt_sha256"], payload["tokenizer_sha256"], len(tokens))

    def verify(self, proof, invocation, request, pin):
        record = self.exchange.store.resolve(proof.receipt_id)
        p = record["payload"]
        if record["kind"] != "MODEL_TOKEN_PREFLIGHT" or (
            p["invocation_sha256"], p["body_sha256"], p["pin_sha256"], p["tokenizer_sha256"], p["input_tokens"]
        ) != (content_digest(invocation), sha256(request.body).hexdigest(), content_digest(pin), pin.tokenizer_sha256, proof.input_tokens):
            raise ContractError("token proof differs from independent source receipt")
        rendered_record = self.exchange.store.resolve(p["render_http_id"])
        token_record = self.exchange.store.resolve(p["tokenize_http_id"])
        original = _decode(request.body, 1114112)
        expected_render = {**original, "_debug_render_only": True, "keep_alive": 30}
        if rendered_record["payload"]["request"]["body_utf8"] != canonical_bytes(expected_render).decode():
            raise ContractError("render receipt changed input beyond declared metadata fields")
        text = rendered_text(decode_response(rendered_record), pin.model.model_id)
        expected_token = {"content": text, "add_special": True, "parse_special": True, "with_pieces": False}
        if token_record["payload"]["request"]["body_utf8"] != canonical_bytes(expected_token).decode():
            raise ContractError("tokenizer did not receive the exact rendered text/policy")
        tokens = token_ids(decode_response(token_record))
        for operation, source in (("render", rendered_record), ("tokenize", token_record)):
            wire = source["payload"]
            expected_endpoint = ENDPOINT if operation == "render" else f"http://127.0.0.1:{p['runtime']['runner']['port']}/tokenize"
            attempt = self.exchange.store.resolve(wire["attempt_id"])
            if (source["kind"] != "MODEL_HTTP_RESPONSE" or wire["operation"] != operation
                    or wire["invocation_sha256"] != content_digest(invocation)
                    or wire["request"]["endpoint"] != expected_endpoint
                    or wire["request"]["body_sha256"] != sha256(wire["request"]["body_utf8"].encode()).hexdigest()
                    or attempt["kind"] != "MODEL_HTTP_ATTEMPT"
                    or attempt["payload"]["body_sha256"] != wire["request"]["body_sha256"]
                    or attempt["payload"]["operation"] != operation
                    or attempt["payload"]["invocation_sha256"] != content_digest(invocation)):
                raise ContractError("preflight source HTTP binding mismatch")
        if tokens != p["token_ids"] or len(tokens) != proof.input_tokens or p["policy"] != TOKEN_POLICY:
            raise ContractError("token proof differs from observed tokenizer IDs")
        if p["rendered_prompt_sha256"] != proof.rendered_prompt_sha256 or sha256(text.encode()).hexdigest() != proof.rendered_prompt_sha256 or tokenizer_identity(p["runtime"]["files"]) != pin.tokenizer_sha256:
            raise ContractError("rendered/tokenizer identity mismatch")
        for role, expected in (("weight", pin.model.artifact_sha256), ("manifest", pin.manifest_sha256), ("template", pin.template_sha256)):
            if p["runtime"]["files"][role]["sha256"] != expected:
                raise ContractError("preflight source artifact identity changed")
        if (len(tokens) > invocation.budget.max_input_tokens_per_call
                or len(tokens) + invocation.budget.max_generated_tokens_per_call > pin.context_tokens):
            raise ContractError("token proof exceeds approved context/input bounds")
        return True
