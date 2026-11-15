"""Controller-only due-event ownership and independent cross-role readback."""
from copy import deepcopy
from datetime import datetime
from hashlib import sha256
import time

from ..contracts import content_digest
from .custody_protocol import envelope
from .generation_transport import need, _ordered, http_bytes


class ControllerDueEvents:
    def __init__(self, *, store, pending_changes, binding, clock, current_state, next_sequence):
        self.store, self.plans, self.binding, self.clock = store,pending_changes,binding,clock
        self.current_state, self.next_sequence = current_state,next_sequence
        self.active = None

    def begin(self, invocation, *, body):
        self.invocation = invocation; self.key = content_digest(invocation)
        self.body,self.wire=body,http_bytes(body)
        self.active = self.plans.claim(invocation.request_sha256)
        self.index = 0; self.previous = None;self.submission=None

    def submitted(self, message):
        need(self.submission is None,'complete-send identity already retained; no resend')
        s = self.store.resolve('generation-sent-'+self.key)
        p = s['payload']; a=self.store.resolve('generation-attempt-'+self.key)
        token=self.store.resolve('token-proof-'+self.key)
        expected={'generation_attempt_id':a['receipt_id'],'generation_http_id':'generation-http-'+self.key,
            'invocation_sha256':self.key,'generation_body_sha256':p['body_sha256'],
            'transport_sent_receipt_sha256':s['sha256'],
            'transport_capture_binding_sha256':content_digest({'clock_id':p['submitted']['clock_id'],'invocation_sha256':self.key}),
            'preflight_receipt_sha256':token['sha256'],
            'clock_binding_sha256':content_digest({'clock_id':p['submitted']['clock_id'],'run_id':self.store.run_id})}
        need(message['payload']==expected and p['request_sha256']==self.invocation.request_sha256
             and p['pending_mode']=='CONTROLLER_DUE_ACK' and a['sequence']<s['sequence']
             and p['body_sha256']==a['payload']['body_sha256']==token['payload']['body_sha256']==sha256(self.body).hexdigest()
             and p['wire_sha256']==sha256(self.wire).hexdigest()
             and p['sent_bytes']==p['wire_bytes']==len(self.wire) and type(p['sent_bytes']) is int,
             'exact durable complete-send proof required')
        self.store.append('controller-submitted-'+self.key,'MODEL_CONTROLLER_SUBMITTED',
            {'invocation_sha256':self.key,'message':message},now=self.clock())
        self.submission=deepcopy(message)
        return True

    def due(self, value):
        need(set(value)=={'submitted_sha256','index','before_response_ready','started'}, 'unknown due-event request')
        need(self.submission is not None and value['submitted_sha256']==content_digest(self.submission),
             'due event lacks the authenticated complete-send receipt')
        need(type(value['index']) is int and value['index']==self.index, 'event ordinal cannot skip or replay')
        p=self.store.resolve('generation-sent-'+self.key)['payload']
        expected=self.submission['payload']
        need(_ordered(p['submitted'],value['started']), 'due request precedes full socket send')
        events=self.active.events if self.active else []
        if self.index==len(events):
            self.store.append('controller-due-complete-'+self.key,'MODEL_CONTROLLER_DUE_COMPLETE',
                {'invocation_sha256':self.key,'applied_count':self.index,'declared_count':len(events)},now=self.clock())
            return {'status':'NO_DUE_EVENT'}
        if value['before_response_ready'] is not False:
            return {'status':'WINDOW_UNAVAILABLE'}
        event=deepcopy(events[self.index])
        def observed_stamp():
            return {'utc':self.clock().isoformat(),'monotonic_ns':time.monotonic_ns(),
                    'clock_id':p['submitted']['clock_id']}
        started=observed_stamp()
        # Intent is retained BEFORE mutation. Any failure leaves this identity
        # spent; a later call cannot blindly reapply it.
        intent='controller-event-intent-'+str(self.index)+'-'+self.key
        need(not any(r['receipt_id']==intent for r in self.store.records()), 'due event already attempted')
        self.store.append(intent,'MODEL_CONTROLLER_EVENT_INTENT',
            {'invocation_sha256':self.key,'declared':event,'ordinal':self.index+1},now=self.clock())
        result=self.active.apply(event)  # trusted closure owns core/venue reads
        completed=observed_stamp()
        timing={'submitted':p['submitted'],'application_started':started,'application_completed':completed}
        need(_ordered(value['started'],started,completed), 'applied event clock order differs')
        observed_state=self.current_state()
        receipt=self.store.append('controller-event-'+str(self.index)+'-'+self.key,'MODEL_CONTROLLER_PENDING_APPLIED',
            {'invocation_sha256':self.key,'ordinal':self.index+1,'declared':event,'event_result':result,
             'timing':timing,'current_state':observed_state},now=self.clock())
        ack={k:expected[k] for k in ('generation_attempt_id','generation_http_id','invocation_sha256',
                                     'generation_body_sha256','transport_sent_receipt_sha256')}
        ack.update(event_receipt_id=receipt['receipt_id'],event_ordinal=self.index+1,
            previous_event_receipt_sha256=self.previous,
            changed_domain={'MARKET':'MARKET','CONTEXT_CHANGE':'CONTEXT','POLICY_CHANGE':'POLICY'}[event['type']],
            before_state_reference_sha256=content_digest(result['before']),
            after_state_reference_sha256=content_digest(result['after']),
            applied_effect_receipt_sha256=receipt['sha256'],applied_timing_receipt_sha256=content_digest(timing),
            current_readback_bundle_sha256=content_digest(observed_state))
        message=envelope('PENDING_APPLIED_ACK',ack,binding=self.binding,
            request_id=self.submission['request_id'],sequence=self.next_sequence(),now=self.clock())
        retained=self.store.append('controller-ack-'+str(self.index)+'-'+self.key,'MODEL_CONTROLLER_PENDING_ACK',
            {'invocation_sha256':self.key,'message':message,'applied_receipt_sha256':receipt['sha256']},now=self.clock())
        self.previous=receipt['sha256']; self.index+=1
        return {'status':'APPLIED','ack_sha256':retained['sha256'],'acknowledgement':message}

    def window(self, record):
        if self.active is None or record['payload']['controller_ack_sha256'] is None: return
        p=record['payload']; applied=self.store.resolve('controller-event-'+str(p['index'])+'-'+self.key)
        e=applied['payload']
        self.active.observations.append({**e['event_result'],'declared':e['declared'],
            'started_at':p['started']['utc'],'completed_at':p['completed']['utc'],
            'transport_receipt_id':record['receipt_id']})


def resolve_remote_windows(store, sent, capture, windows):
    key=sent['payload']['invocation_sha256']; applied=[]; acks=[];previous=None
    submission=store.resolve('controller-submitted-'+key)
    m=submission['payload']['message'];s=sent['payload']
    need(submission['kind']=='MODEL_CONTROLLER_SUBMITTED' and submission['payload']['invocation_sha256']==key
         and sent['sequence']<submission['sequence']<capture['sequence']
         and m['kind']=='GENERATION_SUBMITTED' and m['payload_sha256']==content_digest(m['payload'])
         and m['payload']['invocation_sha256']==key and m['payload']['generation_attempt_id']==s['attempt_id']
         and m['payload']['generation_http_id']=='generation-http-'+key
         and m['payload']['generation_body_sha256']==s['body_sha256']
         and m['payload']['transport_sent_receipt_sha256']==sent['sha256'], 'retained complete-send channel binding differs')
    for index, record in enumerate(windows):
        p=record['payload']
        need(type(p['index']) is int and p['index']==index and p['invocation_sha256']==key
             and p['request_sha256']==sent['payload']['request_sha256'] and p['phase']==sent['payload']['phase']
             and sent['sequence']<record['sequence']<capture['sequence'], 'cross-role window identity differs')
        if p['controller_ack_sha256'] is None: continue
        effect=store.resolve('controller-event-'+str(index)+'-'+key)
        ack=store.resolve('controller-ack-'+str(index)+'-'+key)
        need(effect['kind']=='MODEL_CONTROLLER_PENDING_APPLIED' and ack['kind']=='MODEL_CONTROLLER_PENDING_ACK'
             and ack['sha256']==p['controller_ack_sha256']
             and ack['payload']['applied_receipt_sha256']==effect['sha256']
             and submission['sequence']<effect['sequence']<ack['sequence']<record['sequence']
             and ack['payload']['message']['payload']['applied_effect_receipt_sha256']==effect['sha256'],
             'independent applied acknowledgement differs')
        body=ack['payload']['message']['payload']; e=effect['payload']
        need(e['invocation_sha256']==key and e['ordinal']==index+1
             and body['event_receipt_id']==effect['receipt_id']
             and body['generation_attempt_id']==sent['payload']['attempt_id']
             and body['generation_http_id']=='generation-http-'+key
             and body['generation_body_sha256']==sent['payload']['body_sha256']
             and body['changed_domain']=={'MARKET':'MARKET','CONTEXT_CHANGE':'CONTEXT','POLICY_CHANGE':'POLICY'}[e['declared']['type']]
             and body['event_ordinal']==index+1 and body['previous_event_receipt_sha256']==previous
             and body['invocation_sha256']==key and body['transport_sent_receipt_sha256']==sent['sha256']
             and body['before_state_reference_sha256']==content_digest(e['event_result']['before'])
             and body['after_state_reference_sha256']==content_digest(e['event_result']['after'])
             and body['applied_timing_receipt_sha256']==content_digest(e['timing'])
             and body['current_readback_bundle_sha256']==content_digest(e['current_state']), 'applied ACK source bindings differ')
        previous=effect['sha256']
        applied.append(effect); acks.append(ack)
    done=next((r for r in store.records() if r['receipt_id']=='controller-due-complete-'+key),None)
    if done is not None:
        need(done['kind']=='MODEL_CONTROLLER_DUE_COMPLETE' and done['payload']['invocation_sha256']==key
             and type(done['payload']['applied_count']) is int and type(done['payload']['declared_count']) is int
             and 0<=done['payload']['applied_count']==done['payload']['declared_count']<=8
             and submission['sequence']<done['sequence']<capture['sequence']
             and (not applied or applied[-1]['sequence']<done['sequence']), 'controller completion source differs')
    return {'applied':applied,'acks':acks,'completion':done}


def remote_ordering(observations, transport):
    try:
        remote=transport['remote']; done=remote['completion']; effects=remote['applied']; windows=transport['windows']
        if not done or not effects or done['payload']['applied_count']!=done['payload']['declared_count'] or len(effects)!=len(windows):
            return False
        if len(observations)!=len(effects) or len(effects)!=done['payload']['applied_count']: return False
        previous=transport['request_sent']['payload']['submitted']
        first=transport['response_capture']['payload']['first_bytes']['before_recv']
        for expected, window, effect in zip(observations,windows,effects):
            p=window['payload']; e=effect['payload']; t=e['timing']
            actual={**e['event_result'],'declared':e['declared'],'started_at':p['started']['utc'],
                    'completed_at':p['completed']['utc'],'transport_receipt_id':window['receipt_id']}
            if actual!=expected or p['before_response_ready'] is not False or p['after_response_ready'] is not False or p['error_type'] is not None:
                return False
            if not _ordered(previous,p['started'],t['application_started'],t['application_completed'],p['completed'],p['after_check'],first): return False
            previous=p['after_check']
        return True
    except (KeyError,ValueError,TypeError): return False
