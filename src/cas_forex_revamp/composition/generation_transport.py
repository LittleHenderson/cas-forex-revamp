"""Generation socket observations; no reservation is treated as submission.

This owned composition transport preserves the frozen operator HTTP grammar.
Pending fixture changes run synchronously after full request submission, with
nonblocking response-readiness checks before and after EACH change. A readable
socket, EOF, error or incomplete change fails the pending proof conservatively.
No service is started; constructors and imports are inert.
"""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime
from hashlib import sha256
import errno
import re
import select
import socket
import time
from uuid import uuid4

from ..contracts import ContractError
from ..contracts.primitives import utc_time
from ..operator.ollama_backend import ChatHttpRequest, ChatHttpResponse, ENDPOINT
from ..operator.loopback_http import _Reader, _headers
from ..operator.token_preflight import response_wire


def need(value, why):
    if not value:
        raise ContractError(why)


def http_bytes(body):
    return ("POST /api/chat HTTP/1.1\r\nHost: 127.0.0.1:11434\r\n"
        "Content-Type: application/json\r\nAccept: application/json\r\n"
        "Accept-Encoding: identity\r\nConnection: close\r\n"
        f"Content-Length: {len(body)}\r\n\r\n").encode('ascii') + body


class PendingPlan:
    def __init__(self, events, apply):
        self.events, self.apply = deepcopy(events), apply
        self.claimed = False
        self.observations = []


class PendingChangeBridge:
    """Trusted in-process binding, selected by the runner, never imported data."""
    def __init__(self):
        self.active = {}
        self.used = set()

    @contextmanager
    def register(self, request_sha256, *, events, apply):
        need(request_sha256 not in self.used and not self.active and callable(apply)
             and type(events) is list and 1 <= len(events) <= 8, 'one exact pending plan required')
        self.used.add(request_sha256)
        plan = PendingPlan(events, apply)
        self.active[request_sha256] = plan
        try:
            yield plan
        finally:
            self.active.pop(request_sha256)

    def claim(self, request_sha256):
        plan = self.active.get(request_sha256)
        need(not self.active or plan is not None, 'transport request differs from active pending request')
        if plan:
            need(not plan.claimed, 'pending plan cannot be reused')
            plan.claimed = True
        return plan


class _ObservedReader(_Reader):
    def __init__(self, connection, deadline, ready, stamp):
        super().__init__(connection, deadline, ready)
        self.stamp, self.first = stamp, None

    def receive(self):
        while True:
            self.ready(self.connection, self.deadline)
            lower = self.stamp()
            try:
                chunk = self.connection.recv(4096)
            except BlockingIOError:
                continue
            upper = self.stamp()
            if chunk and self.first is None:
                self.first = {'before_recv': lower, 'after_recv': upper}
            return chunk


class GenerationClient:
    """One fixed loopback generation request with transport-owned observations.

    socket_factory/select_fn are development-test seams. Production uses socket
    and select directly. No retries, DNS, proxies, redirects or environment read.
    """
    def __init__(self, *, store, phase, invocation_sha256, request_sha256, clock,
                 pending=None, socket_factory=socket.socket, select_fn=select.select,
                 monotonic=time.monotonic, monotonic_ns=time.monotonic_ns):
        self.store, self.phase, self.key, self.request_hash = store, phase, invocation_sha256, request_sha256
        self.clock, self.pending = clock, pending
        self.socket_factory, self.select = socket_factory, select_fn
        self.monotonic, self.monotonic_ns = monotonic, monotonic_ns
        self.clock_id = 'transport-'+uuid4().hex
        self.used = False

    def stamp(self):
        return {'utc': utc_time(self.clock(), 'transport clock').isoformat(),
                'monotonic_ns': self.monotonic_ns(), 'clock_id': self.clock_id}

    def record(self, suffix, kind, payload):
        return self.store.append('generation-'+suffix+'-'+self.key, kind,
            {'invocation_sha256':self.key,'request_sha256':self.request_hash,'phase':self.phase,**payload}, now=self.clock())

    def ready(self, connection, deadline, *, write=False):
        remaining = deadline-self.monotonic()
        if remaining <= 0: raise TimeoutError('generation transport deadline exceeded')
        readable, writable, failed = self.select([] if write else [connection],
            [connection] if write else [], [connection], remaining)
        if failed: raise ConnectionError('generation socket failed')
        if not (writable if write else readable): raise TimeoutError('generation transport deadline exceeded')

    def pending_changes(self, connection, deadline):
        if self.pending is None: return
        for index, event in enumerate(self.pending.events):
            need(self.monotonic() < deadline, 'pending change window expired')
            readable, _, failed = self.select([connection], [], [connection], 0)
            before_ready = bool(readable or failed)
            start = self.stamp()
            result, error = None, None
            if not before_ready:
                try:
                    result = self.pending.apply(deepcopy(event))
                except Exception as exc:
                    error = type(exc).__name__
            completed = self.stamp()
            readable, _, failed = self.select([connection], [], [connection], 0)
            after_ready = bool(readable or failed)
            checked = self.stamp()
            payload = {'index':index,'declared':event,'before_response_ready':before_ready,
                'after_response_ready':after_ready,'started':start,'completed':completed,
                'after_check':checked,'event_result':result,'error_type':error}
            receipt = self.record('pending-'+str(index), 'MODEL_TRANSPORT_PENDING_WINDOW', payload)
            if result is not None:
                observation = {**result,'declared':event,'started_at':start['utc'],
                    'completed_at':completed['utc'],'transport_receipt_id':receipt['receipt_id']}
                self.pending.observations.append(observation)
            if before_ready or after_ready or error is not None:
                break  # consume the actual response; never submit again or grade this as pending success

    def post(self, request):
        need(not self.used, 'generation transport is one-shot'); self.used = True
        need(isinstance(request,ChatHttpRequest) and request.endpoint == ENDPOINT, 'fixed generation endpoint required')
        need(type(request.body) is bytes and 0 < len(request.body) <= 1114112, 'bounded generation body required')
        need(type(request.timeout_seconds) is int and 0 < request.timeout_seconds <= 120, 'bounded generation timeout required')
        need(type(request.response_byte_limit) is int and 0 < request.response_byte_limit <= 65536, 'bounded generation response required')
        utc_time(request.absolute_deadline, 'absolute_deadline')
        remaining = min(request.timeout_seconds,(request.absolute_deadline-self.clock()).total_seconds())
        if remaining <= 0: raise TimeoutError('generation window expired')
        deadline = self.monotonic()+remaining
        attempt = self.store.resolve('generation-attempt-'+self.key)
        need(attempt['kind']=='MODEL_HTTP_ATTEMPT' and attempt['payload']['operation']=='generation'
             and attempt['payload']['invocation_sha256']==self.key
             and attempt['payload']['phase']==self.phase
             and attempt['payload']['body_sha256']==sha256(request.body).hexdigest(), 'durable matching reservation required')
        wire = http_bytes(request.body)
        connection = self.socket_factory(socket.AF_INET,socket.SOCK_STREAM)
        try:
            connection.setblocking(False)
            status = connection.connect_ex(('127.0.0.1',11434))
            need(status in {0,errno.EINPROGRESS,errno.EWOULDBLOCK,errno.EALREADY,getattr(errno,'WSAEWOULDBLOCK',10035)}, 'loopback connection failed')
            self.ready(connection,deadline,write=True)
            if connection.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR): raise ConnectionError('loopback connection failed')
            offset = 0
            while offset < len(wire):
                self.ready(connection,deadline,write=True)
                try: sent = connection.send(memoryview(wire)[offset:])
                except BlockingIOError: continue
                if sent <= 0: raise ConnectionError('generation request interrupted')
                offset += sent
            # This boundary is AFTER every header/body byte was accepted by send.
            submitted = self.stamp()
            self.record('sent','MODEL_TRANSPORT_REQUEST_SENT',{'attempt_id':attempt['receipt_id'],
                'endpoint':ENDPOINT,'body_sha256':sha256(request.body).hexdigest(),
                'wire_sha256':sha256(wire).hexdigest(),'wire_bytes':len(wire),'sent_bytes':offset,
                'submitted':submitted,'pending_events':self.pending.events if self.pending else []})
            self.pending_changes(connection,deadline)
            reader = _ObservedReader(connection,deadline,self.ready,self.stamp)
            status_code,fields = _headers(reader.until(b'\r\n\r\n',16384))
            need(fields.get('content-encoding','identity').lower()=='identity','compressed response unsupported')
            length,transfer=fields.get('content-length'),fields.get('transfer-encoding')
            need(length is None or transfer is None,'ambiguous response framing')
            maximum=request.response_byte_limit
            if transfer is not None:
                need(transfer.lower()=='chunked','unsupported transfer encoding');body=bytearray()
                while True:
                    line=reader.until(b'\r\n',32)
                    need(re.fullmatch(rb'[0-9A-Fa-f]{1,16}',line),'invalid chunk length')
                    size=int(line,16)
                    if size==0:
                        need(reader.until(b'\r\n',4096)==b'','trailers unsupported');break
                    need(len(body)+size<=maximum,'response exceeds ceiling')
                    body.extend(reader.exact(size));need(reader.exact(2)==b'\r\n','invalid chunk terminator')
                result=bytes(body)
            elif length is not None:
                need(re.fullmatch(r'[0-9]{1,8}',length) and int(length)<=maximum,'invalid/excessive content length')
                result=reader.exact(int(length))
            else:result=reader.to_eof(maximum)
            completed=self.stamp()
            if self.monotonic()>=deadline:raise TimeoutError('generation response exceeded deadline')
            need(reader.first is not None,'response receipt lacks socket observation')
            response=ChatHttpResponse(status_code,fields.get('content-type',''),result)
            self.record('capture','MODEL_TRANSPORT_RESPONSE_CAPTURE',{'first_bytes':reader.first,
                'completed':completed,'response':response_wire(response)})
            return response
        finally:connection.close()


def _ordered(*stamps):
    if not stamps:return False
    if any(type(x.get('monotonic_ns')) is not int or x['monotonic_ns']<0 for x in stamps):return False
    if len({x['clock_id'] for x in stamps})!=1:return False
    moments=[utc_time(datetime.fromisoformat(x['utc'].replace('Z','+00:00')),'transport stamp') for x in stamps]
    return all(a<=b for a,b in zip(moments,moments[1:])) and all(a['monotonic_ns']<b['monotonic_ns'] for a,b in zip(stamps,stamps[1:]))


def verify_generation_transport(store, invocation_sha256):
    """Resolve separate durable socket observations; never promote old timestamps."""
    key=invocation_sha256
    sent=store.resolve('generation-sent-'+key);capture=store.resolve('generation-capture-'+key)
    http=store.resolve('generation-http-'+key);attempt=store.resolve('generation-attempt-'+key)
    s,c,h,a=sent['payload'],capture['payload'],http['payload'],attempt['payload']
    need(sent['kind']=='MODEL_TRANSPORT_REQUEST_SENT' and capture['kind']=='MODEL_TRANSPORT_RESPONSE_CAPTURE'
         and http['kind']=='MODEL_HTTP_RESPONSE' and attempt['kind']=='MODEL_HTTP_ATTEMPT','actual transport observations required')
    need(all(x['invocation_sha256']==key for x in (s,c,h,a)) and h['operation']==a['operation']=='generation'
         and s['attempt_id']==attempt['receipt_id'] and h['attempt_id']==attempt['receipt_id']
         and s['phase']==c['phase']==a['phase'] and s['request_sha256']==c['request_sha256'],'transport identity differs')
    wire=http_bytes(h['request']['body_utf8'].encode('utf-8'))
    need(s['endpoint']==h['request']['endpoint']==ENDPOINT
         and s['body_sha256']==h['request']['body_sha256']==a['body_sha256']==sha256(h['request']['body_utf8'].encode()).hexdigest()
         and type(s['sent_bytes']) is int and type(s['wire_bytes']) is int
         and s['sent_bytes']==s['wire_bytes']==len(wire)
         and s['wire_sha256']==sha256(wire).hexdigest() and c['response']==h['response'],'request submission/response bytes differ')
    need(attempt['sequence']<sent['sequence']<capture['sequence']<http['sequence'],'transport journal order differs')
    need(_ordered(s['submitted'],c['first_bytes']['before_recv'],c['first_bytes']['after_recv'],c['completed']), 'transport clocks do not establish order')
    start=datetime.fromisoformat(h['started_at'].replace('Z','+00:00'));end=datetime.fromisoformat(h['completed_at'].replace('Z','+00:00'))
    need(start<=datetime.fromisoformat(s['submitted']['utc'])<=datetime.fromisoformat(c['completed']['utc'])<=end,'transport is outside enclosing exchange')
    windows=[r for r in store.records() if r['kind']=='MODEL_TRANSPORT_PENDING_WINDOW' and r['payload']['invocation_sha256']==key]
    if s.get('pending_mode') == 'CONTROLLER_DUE_ACK':
        from .remote_pending import resolve_remote_windows
        remote = resolve_remote_windows(store, sent, capture, windows)
        return {'request_sent':sent,'response_capture':capture,'windows':windows,
                'request_sha256':s['request_sha256'],'invocation_sha256':key, 'remote':remote}
    need(len(windows)<=len(s['pending_events']) and all(sent['sequence']<r['sequence']<capture['sequence'] for r in windows),'pending journal span differs')
    for index,r in enumerate(windows):
        p=r['payload'];need(p['index']==index and p['declared']==s['pending_events'][index]
            and p['request_sha256']==s['request_sha256'] and p['phase']==s['phase'],'pending event identity differs')
    return {'request_sent':sent,'response_capture':capture,'windows':windows,
            'request_sha256':s['request_sha256'],'invocation_sha256':key}


def pending_ordering(observations, transport):
    """Independent pure reconstruction, also used by retained-attempt readback."""
    try:
        if 'remote' in transport:
            from .remote_pending import remote_ordering
            return remote_ordering(observations, transport)
        s=transport['request_sent']['payload'];c=transport['response_capture']['payload'];windows=transport['windows']
        if not s['pending_events'] or len(windows)!=len(s['pending_events']) or len(observations)!=len(windows):return False
        previous=s['submitted']
        for event,record in zip(observations,windows):
            p=record['payload']
            expected={**p['event_result'],'declared':p['declared'],'started_at':p['started']['utc'],
                      'completed_at':p['completed']['utc'],'transport_receipt_id':record['receipt_id']} if type(p['event_result']) is dict else None
            if (p['before_response_ready'] is not False or p['after_response_ready'] is not False
                    or p['error_type'] is not None or expected!=event
                    or not _ordered(previous,p['started'],p['completed'],p['after_check'],c['first_bytes']['before_recv'])):return False
            previous=p['after_check']
        return True
    except (ValueError,KeyError,TypeError):
        return False
