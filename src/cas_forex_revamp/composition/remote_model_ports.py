"""Runner-side evidence RPC and transport observation. No venue/core/custody IO."""
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from ..contracts import canonical_bytes, content_digest
from ..operator.model_evidence import ModelEvidenceStore
from ..operator.ollama_backend import ENDPOINT
from ..operator.stage_b import StageBModelPorts
from .generation_transport import GenerationClient, need, verify_generation_transport
from .custody_protocol import envelope


class CurrentModelStore(ModelEvidenceStore):
    """A scoped model-evidence port; the actual store remains in the controller.

    The fixed placeholder satisfies the frozen nominal interface but no method
    can open it. Controller RPC restricts reads and writes to the active exact
    invocation. It cannot expose previous/future cases or any authority store.
    """
    def __init__(self, channel, *, run_id, deadline):
        super().__init__(Path('/unavailable/current.model-evidence.sqlite3'),run_id=run_id,deadline=deadline)
        self.channel = channel

    def _db(self, **kwargs): raise RuntimeError('runner has no model database access')
    def initialize(self, **kwargs): raise RuntimeError('runner cannot initialize evidence')
    def records(self): return tuple(self.channel.call('STORE_RECORDS', {}))
    def verified_records(self): return self.records()
    def resolve(self, receipt_id): return self.channel.call('STORE_RESOLVE', {'receipt_id':receipt_id})
    def checkpoint(self): return tuple(self.channel.call('STORE_CHECKPOINT', {}))
    def append(self, receipt_id, kind, payload, *, now):
        return self.channel.call('STORE_APPEND', {'receipt_id':receipt_id,'kind':kind,
            'payload':__import__('json').loads(canonical_bytes(payload)),'now':now.isoformat()})
    def begin_http(self, **kwargs):
        return self.channel.call('STORE_BEGIN', __import__('json').loads(canonical_bytes(kwargs)))


class RemoteGenerationClient(GenerationClient):
    """Full-send boundary is inherited unchanged; only due-event RPC is new."""
    def __init__(self, *, channel, request_id, **kwargs):
        super().__init__(pending=None, **kwargs)
        self.channel,self.request_id = channel,request_id

    def record(self, suffix, kind, payload):
        if kind == 'MODEL_TRANSPORT_REQUEST_SENT':
            payload = dict(payload)
            payload.pop('pending_events')
            payload['pending_mode'] = 'CONTROLLER_DUE_ACK'
        return super().record(suffix,kind,payload)

    def pending_changes(self, connection, deadline):
        # Includes receipt reads, submit acknowledgement, every event RPC and
        # their evidence writes. The transport's original monotonic cap is not reset.
        with self.channel.bounded(until=deadline):
            return self._pending_changes(connection,deadline)

    def _pending_changes(self, connection, deadline):
        sent = self.store.resolve('generation-sent-'+self.key)
        token = self.store.resolve('token-proof-'+self.key)
        base = {'generation_attempt_id':'generation-attempt-'+self.key,
            'generation_http_id':'generation-http-'+self.key,'invocation_sha256':self.key,
            'generation_body_sha256':sent['payload']['body_sha256'],
            'transport_sent_receipt_sha256':sent['sha256'],
            'transport_capture_binding_sha256':content_digest({'clock_id':self.clock_id,'invocation_sha256':self.key}),
            'preflight_receipt_sha256':token['sha256'],
            'clock_binding_sha256':content_digest({'clock_id':self.clock_id,'run_id':self.store.run_id})}
        submitted=envelope('GENERATION_SUBMITTED',base,binding=self.channel.custody_binding,
            request_id=self.request_id,sequence=self.channel.public_sequence+1,now=self.clock())
        self.channel.accept_public(submitted,self.channel.custody_binding)
        need(self.channel.call('GENERATION_SUBMITTED',submitted) is True,'complete-send receipt was not retained')
        previous=None
        # Only applied acknowledgement digests cross back. No event payload or
        # count of the remaining schedule is ever sent to this process.
        for index in range(9):
            need(self.monotonic() < deadline, 'pending RPC window expired')
            readable, _, failed = self.select([connection],[],[connection],0)
            before_ready = bool(readable or failed); start = self.stamp()
            ack, error = None, None
            try:
                ack = self.channel.call('DUE_EVENT', {'submitted_sha256':content_digest(submitted),'index':index,
                    'before_response_ready':before_ready,'started':start})
            except Exception as exc:
                error = type(exc).__name__
                if self.channel.closed:
                    raise  # preserve timeout; no receipt RPC on an incomplete channel
            completed = self.stamp()
            readable, _, failed = self.select([connection],[],[connection],0)
            after_ready = bool(readable or failed); checked = self.stamp()
            if ack is not None and ack['status'] == 'NO_DUE_EVENT':
                break
            if ack is not None and ack['status']=='APPLIED':
                message=self.channel.accept_public(ack['acknowledgement'],self.channel.custody_binding)
                p=message['payload']
                need(message['kind']=='PENDING_APPLIED_ACK' and all(p[k]==base[k] for k in (
                    'generation_attempt_id','generation_http_id','invocation_sha256','generation_body_sha256',
                    'transport_sent_receipt_sha256')) and p['event_ordinal']==index+1
                     and p['previous_event_receipt_sha256']==previous,'applied event acknowledgement binding differs')
                previous=p['applied_effect_receipt_sha256']
            self.record('pending-'+str(index),'MODEL_TRANSPORT_PENDING_WINDOW', {
                'index':index,'before_response_ready':before_ready,'after_response_ready':after_ready,
                'started':start,'completed':completed,'after_check':checked,
                'controller_ack_sha256':ack['ack_sha256'] if ack and ack['status']=='APPLIED' else None,
                'error_type':error})
            if before_ready or after_ready or error is not None or not ack or ack['status'] != 'APPLIED': break


class RemoteObservedPorts(StageBModelPorts):
    def __init__(self, *, channel, **kwargs):
        super().__init__(**kwargs); self.channel = channel

    def count(self, invocation, request, pin):
        key=content_digest(invocation)
        need(key not in self._deadlines,'preflight is one-shot')
        # The controller minted this deadline before exposing the current frame.
        # Do not start a new per-call clock on receipt, preflight or generation.
        deadline=min(self.store.deadline,request.absolute_deadline,self.channel.invocation_deadline)
        self._deadlines[key]=deadline
        with self.channel.bounded(deadline=deadline):
            return self.preflight.count(invocation,replace(request,absolute_deadline=deadline),pin)

    def post(self, request):
        need(self._active is not None, 'generation lacks exact preflight')
        invocation, expected = self._active; self._active = None
        need(request == expected and request.endpoint == ENDPOINT, 'generation body changed')
        self.runtime.require_same(self._token(invocation)['runtime'])
        key = content_digest(invocation)
        bounded = replace(request, absolute_deadline=min(request.absolute_deadline,self._deadlines[key]))
        client = RemoteGenerationClient(channel=self.channel,request_id=__import__('json').loads(invocation.packet_json)['request_id'],
            store=self.store,phase=self.phase,
            invocation_sha256=key,request_sha256=invocation.request_sha256,clock=self.clock)
        with self.channel.bounded(deadline=bounded.absolute_deadline):
            response, _ = self.exchange.post(invocation,bounded,operation='generation',client=client)
        return response

    def verify(self, reply, invocation):
        super().verify(reply,invocation)
        # Controller reconstructs the cross-role ordering independently. The
        # runner cannot read private applied-event records to certify itself.
        return self.channel.call('VERIFY_TRANSPORT', {'invocation_sha256':content_digest(invocation)}) is True
