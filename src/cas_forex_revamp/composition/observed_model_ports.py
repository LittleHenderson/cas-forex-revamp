"""B-only transport composition; frozen operator implementation stays unchanged."""
from dataclasses import replace

from ..contracts import content_digest
from ..operator.ollama_backend import ENDPOINT
from ..operator.stage_b import StageBModelPorts
from .generation_transport import GenerationClient, need, verify_generation_transport


class ObservedModelPorts(StageBModelPorts):
    def __init__(self, *, pending_changes=None, **kwargs):
        super().__init__(**kwargs)
        self.pending_changes=pending_changes

    def post(self, request):
        need(self._active is not None,'generation lacks preflight binding')
        invocation,expected=self._active;self._active=None
        need(request==expected and request.endpoint==ENDPOINT,'generation request changed')
        self.runtime.require_same(self._token(invocation)['runtime'])
        key=content_digest(invocation)
        bounded=replace(request,absolute_deadline=min(request.absolute_deadline,self._deadlines[key]))
        pending=self.pending_changes.claim(invocation.request_sha256) if self.pending_changes else None
        client=GenerationClient(store=self.store,phase=self.phase,invocation_sha256=key,
            request_sha256=invocation.request_sha256,clock=self.clock,pending=pending)
        response,_=self.exchange.post(invocation,bounded,operation='generation',client=client)
        return response

    def verify(self, reply, invocation):
        super().verify(reply,invocation)
        observed=verify_generation_transport(self.store,content_digest(invocation))
        need(observed['request_sha256']==invocation.request_sha256,'transport request binding differs')
        return True
