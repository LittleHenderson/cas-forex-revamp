"""Explicit B evidence binding; no model start or execution authority."""
from __future__ import annotations

from hashlib import sha256
from ..contracts import ContractError, canonical_bytes, content_digest
from ..core.storage import decode
from ..operator.model import InferenceReply, ModelInvocation
from .custody_evidence_store import CustodyModelEvidenceStore


class AnchoredModelStore(CustodyModelEvidenceStore):
    """Commit each model receipt, then retain its high-water mark separately.

    Failure to anchor propagates before transport or admission. The two stores
    are not an atomic database. A suffix after an interrupted anchor is retained
    and must be reconciled; it never becomes permission to retry a generation.
    """
    def bind_journal(self, journal, scope, clock):
        self._anchor_journal, self._anchor_scope, self._anchor_clock = journal, scope, clock

    def _anchor(self):
        sequence, digest = self.checkpoint()
        self._anchor_journal.append('model-prefix-' + str(sequence), 'MODEL_CHECKPOINT',
            self._anchor_scope, {'sequence': sequence, 'sha256': digest}, now=self._anchor_clock())

    def append(self, *args, **kwargs):
        record = super().append(*args, **kwargs)
        self._anchor()
        return record

    def begin_http(self, **kwargs):
        record = super().begin_http(**kwargs)
        self._anchor()  # durable generation reservation is anchored BEFORE HTTP
        return record

    def verified_records(self):
        first = self.records()
        anchors = [r for r in self._anchor_journal.records() if r.kind == 'MODEL_CHECKPOINT']
        expected = (len(first), first[-1]['sha256'] if first else '0' * 64)
        if not anchors or (anchors[-1].payload['sequence'], anchors[-1].payload['sha256']) != expected:
            raise ContractError('model prefix lacks an independently retained complete anchor')
        if self.records() != first:
            raise ContractError('model evidence changed while binding its prefix')
        return first


class ModelDecisionReader:
    """Read an already observed inference through independent source ports.

    The constructor receives the trusted ports/store; imported decision JSON
    cannot appoint them. Raw model text, exact token/runtime and usage receipts
    stay separate from the simulator observation and admission/effect records.
    """
    def __init__(self, store, ports, *, expected_adapter_id, require_transport=False):
        from ..contracts.primitives import identifier
        self.expected_adapter_id = identifier(expected_adapter_id, 'expected adapter id')
        self.store, self.ports = store, ports
        self.require_transport = require_transport

    def __call__(self, request, result):
        records = self.store.verified_records()
        by_id = {r['receipt_id']: r for r in records}
        provenance = result['provenance']
        record = by_id.get(provenance['inference_receipt_id'])
        if record is None or record['kind'] != 'MODEL_INFERENCE_RECEIPT':
            raise ContractError('actual inference source unavailable')
        payload = record['payload']
        invocation = decode(canonical_bytes(payload['invocation']).decode(), ModelInvocation)
        reply = decode(canonical_bytes(dict(raw_selection_json=payload['raw_selection_json'],
            receipt_id=record['receipt_id'], invocation_sha256=payload['invocation_sha256'],
            model=payload['requested_model'], started_at=payload['started_at'],
            completed_at=payload['completed_at'], input_tokens=payload['observed_provider_input_tokens'],
            generated_tokens=payload['observed_provider_generated_tokens'])).decode(), InferenceReply)
        if self.ports.verify(reply, invocation) is not True:
            raise ContractError('independent inference verification failed')
        from ..contracts import selection_from_json
        from ..contracts import DecisionRequest
        from ..operator.decisions import decision_identity
        typed_request = decode(canonical_bytes(request).decode(), DecisionRequest)
        selection = selection_from_json(reply.raw_selection_json, typed_request)
        if (provenance['origin'] != 'ACTUAL_MODEL'
                or provenance['adapter_id'] != self.expected_adapter_id
                or provenance['prompt_version'] != invocation.model.prompt_version
                or result['decision_id'] != decision_identity(typed_request)
                or content_digest(request) != invocation.request_sha256
                or provenance['request_sha256'] != invocation.request_sha256
                or canonical_bytes(selection) != canonical_bytes(result['selection'])
                or provenance['response_sha256'] != sha256(reply.raw_selection_json.encode()).hexdigest()
                or provenance['model_id'] != reply.model.model_id
                or provenance['model_artifact_sha256'] != reply.model.artifact_sha256
                or provenance['started_at'] != payload['started_at']
                or provenance['completed_at'] != payload['completed_at']):
            raise ContractError('decision differs from independent inference source')
        ids = (payload['generation_http_id'], payload['token_proof_id'],
               payload['runtime_before_id'], payload['runtime_after_id'])
        dependencies = [by_id[key] for key in ids]
        answer = {'receipt': record, 'sources': dependencies,
                'invocation_sha256': content_digest(invocation),
                'budget': invocation.budget, 'requested_reasoning': reply.model.reasoning_effort,
                'latency_ms': int((reply.completed_at-reply.started_at).total_seconds()*1000)}
        if self.require_transport:
            from .generation_transport import verify_generation_transport
            answer['transport'] = verify_generation_transport(self.store,content_digest(invocation))
        return answer
