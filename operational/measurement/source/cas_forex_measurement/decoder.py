"""Authenticated raw capture decoding. Derivation is not method acceptance.

The producer uses separately authenticated inputs; the consumer repeats decoding
from the complete signed EventInputs. No synthetic normalized fallback exists.
"""
from __future__ import annotations
import array
import hashlib
import hmac
from dataclasses import dataclass
import os
import socket
import struct
from cas_forex_operational_contracts import capture as c, method as m
from cas_forex_operational_contracts.common import (canonical_bytes,decode_canonical,digest,require,
    ContractError,DependencyUnavailable,utc,MAX_OBJECT)
from cas_forex_operational_contracts.validation import verify_reference_bytes
from .capture import snapshot
from .inventory import parse_stat
from .installation import ABI_LAYOUT
from .calibration import public_fixture_key


def one(values,code):
    require(len(values)==1,code)
    return values[0]


def same_subject(a,b):
    return all(a[k]==b[k] for k in ('boot_id','pid','start_ticks','parent_pid','uid','gid'))


@dataclass(frozen=True)
class ProducerInputs:
    """Untrusted references until explicit decode verifies each signed body."""
    runtime_selection: dict
    selected_values: dict
    selected_source_refs: tuple
    raw_blob_manifests: tuple
    spawn_selection: dict | None = None


class AuthenticatedGraph:
    def __init__(self,*,owner,now):
        self.owner,self.now=owner,now;self.derived=[];self.ops=[];self.manifests=[]
        self.inputs=None;self.spawn=None;self.predecessors=[]
    def bytes(self,ref):
        raw=self.owner.evidence.resolve(ref);verify_reference_bytes(ref,raw)
        return raw
    def authenticated(self,pair,type_name,kind):
        c.validate('AuthenticatedMethodObject',pair)
        require(pair['object_ref']['artifact_kind']==kind and pair['envelope_ref']['artifact_kind']=='SIGNED_ENVELOPE','AUTHENTICATED_KIND')
        raw=self.bytes(pair['object_ref']);env=m.decode('SignedEnvelope',self.bytes(pair['envelope_ref'])).payload()
        body=env['body'];require(body['binding']==self.owner.budget['binding'] and body['budget_sha256']==self.owner.budget_hash,'AUTHENTICATED_CONTEXT')
        require(body['record_sha256']==digest(raw) and body['record_bytes']==len(raw),'AUTHENTICATED_BYTES')
        require(self.owner.auth.verify_attestation(raw,env,expected_purpose='policy-inheritance-witness-v3',
            appointment=self.owner.appointment,now=self.now) is None,'AUTHENTICATION_REJECTED')
        module=m if type_name in ('Event','CoveragePlan') else c
        result=module.decode(type_name,raw).payload()
        if 'producer_id' in result:require(result['producer_id']==body['producer_id'],'ATTESTED_PRODUCER_MISMATCH')
        return result
    def derive(self,kind,value):
        raw=canonical_bytes(value,limit=MAX_OBJECT);ref=self.owner.sink.retain(raw,artifact_kind=kind)
        verify_reference_bytes(ref,raw);require(ref['artifact_kind']==kind and self.owner.sink.readback(ref)==raw,'DERIVED_RETENTION')
        if (ref,raw) not in self.derived:self.derived.append((snapshot(ref),raw))
        return ref
    def raw(self,ref,selector=None,subject=None):
        matches=[x for x in self.manifests if x['blob_ref']==ref and (selector is None or x['source_selector']==selector)
                 and (subject is None or x['subject']==subject)]
        require(matches,'RAW_MANIFEST_UNAVAILABLE')
        raw=self.bytes(ref)
        require(all(x['raw_bytes']==len(raw) and x['raw_sha256']==digest(raw) for x in matches),'RAW_MANIFEST_BYTES')
        return raw
    def operations(self,kind,*,subject=None):
        return [x for x in self.ops if x['kind']==kind and (subject is None or x['data'].get('subject')==subject)]
    def operation(self,ref,kind):
        value=c.decode('CaptureOperation',self.bytes(ref)).payload()
        require(value['kind']==kind and any(value==self.clean(x) for x in self.ops),'OPERATION_NOT_CAPTURED')
        return value
    def prepare(self,captures,selection):
        owner=self.owner;budget=owner.budget
        require(utc(budget['started']['utc'])<=utc(self.now['utc'])<utc(budget['deadline']['utc'])
            and budget['started']['boottime_ns']<=self.now['boottime_ns']<budget['deadline']['boottime_ns'],'DECODER_DEADLINE')
        if owner.event_inputs is not None:
            self.inputs=self.authenticated(owner.event_inputs,'EventInputs','AUTHENTICATED_EVENT_INPUTS')
            require(self.inputs['capture_objects']==list(captures),'CAPTURE_SELECTION_MISMATCH')
            configured=self.inputs
        else:
            require(owner.producer_inputs is not None,'DECODER_CONTEXT_UNAVAILABLE')
            configured=owner.producer_inputs
        get=lambda key:configured[key] if isinstance(configured,dict) else getattr(configured,key)
        selected=self.authenticated(get('selected_values'),'RuntimeSelectedValues','RUNTIME_SELECTED_VALUES')
        runtime=self.authenticated(get('runtime_selection'),'RuntimeSelectionBinding','RUNTIME_SELECTION_BINDING')
        require(selected==selection,'SELECTED_VALUES_MISMATCH')
        require(selected['binding']==budget['binding'] and selected['budget_sha256']==owner.budget_hash,'SELECTED_CONTEXT')
        for key in ('binding','budget_sha256','slot_id','subject_id'):require(runtime[key]==selected[key],'RUNTIME_SELECTION_CONTEXT')
        require(runtime['selection_ref']==get('selected_values')['object_ref'] and runtime['selected_decoder_sha256']==owner.component,'RUNTIME_DECODER_PIN')
        require(runtime['selected_source_refs']==list(get('selected_source_refs')),'SELECTED_SOURCE_SET')
        self.selected=selected;self.runtime=runtime;self.source_refs=list(get('selected_source_refs'))
        if self.inputs:
            for key in ('binding','budget_sha256','slot_id','event_kind'):require(self.inputs[key]==selected[key],'EVENT_INPUT_CONTEXT')
        slot=one([x for x in owner.plan['slots'] if x['slot_id']==selected['slot_id']],'COVERAGE_SLOT')
        require(slot['kind']==selected['event_kind'] and slot['expected_subject_id']==selected['subject_id']
            and slot['payload_decoder_sha256']==owner.component,'COVERAGE_DECODER_SELECTION')
        require(digest(canonical_bytes(owner.plan))==budget['coverage_plan_sha256'],'COVERAGE_PLAN_PIN')
        if get('spawn_selection') is not None:
            self.spawn=self.authenticated(get('spawn_selection'),'SpawnSelection','TRUSTED_SPAWN_SELECTION')
            require(self.spawn['binding']==budget['binding'] and self.spawn['budget_sha256']==owner.budget_hash,'SPAWN_CONTEXT')
        require(bool(self.spawn)==(selected['event_kind'] in ('RUNNER_INSTALL','MODEL_INSTALL')),'SPAWN_STAGE')
        for pair in get('raw_blob_manifests'):
            item=self.authenticated(pair,'RawBlobManifest','RAW_BLOB_MANIFEST')
            require(item['binding']==budget['binding'] and item['budget_sha256']==owner.budget_hash,'RAW_CONTEXT')
            require(item['finished']['boottime_ns']<=self.now['boottime_ns'] and utc(item['finished']['utc'])<=utc(self.now['utc']),'RAW_FUTURE')
            self.manifests.append(item)
        seen=set()
        for pair in captures:
            require(pair['object_ref']['sha256'] not in seen,'DUPLICATE_CAPTURE');seen.add(pair['object_ref']['sha256'])
            batch=self.authenticated(pair,'CaptureBatch','TRUSTED_CAPTURE_BATCH')
            require(batch['binding']==budget['binding'] and batch['budget_sha256']==owner.budget_hash,'CAPTURE_CONTEXT')
            require(batch['started']['boottime_ns']>=budget['started']['boottime_ns'] and batch['finished']['boottime_ns']<=self.now['boottime_ns']
                and utc(batch['started']['utc'])>=utc(budget['started']['utc']) and utc(batch['finished']['utc'])<=utc(self.now['utc']),'CAPTURE_INTERVAL')
            for op in batch['operations']:
                item=snapshot(op);item['_batch']=pair['object_ref'];item['_subject']=batch['subject'];item['_origin']=batch['reporting_origin']
                # Internal metadata is stripped before exact operation byte comparisons.
                self.ops.append(item)
        require(self.ops,'RAW_EVIDENCE_UNAVAILABLE')
        for op in self.ops:
            if op['kind']=='INSTALL_CALL':
                wanted='DECISION_BOOTSTRAP' if selected['event_kind']=='RUNNER_INSTALL' else 'MODEL_BOOTSTRAP'
                require(op['_origin']==wanted and op['_subject']==op['data']['subject'],'INSTALL_REPORTING_ORIGIN')
            if op['kind']=='SPAWN':
                wanted='CONTROLLER' if op['data']['role']=='RUNNER_INSTALL' else 'DECISION_BOOTSTRAP'
                require(op['_origin']==wanted and op['_subject']==op['data']['parent'],'SPAWN_REPORTING_ORIGIN')
        # Every raw byte use has both an appointed manifest and an appointed actual operation.
        for op in self.ops:
            if op['kind']=='PROC_READ':
                data=op['data'];raw=self.raw(data['raw_ref'],data['selector'],data['subject'])
                require(data['errno']==0 and data['return_value']==len(raw),'PROC_READ_FAILED')
        for ref in self.source_refs:
            self.bytes(ref)
            if ref['artifact_kind']=='EVENT_RECORD':
                require(callable(owner.accepted_event),'PREDECESSOR_RESOLVER_UNAVAILABLE')
                raw=owner.accepted_event(ref,now=self.now);verify_reference_bytes(ref,raw)
                event=m.decode('Event',raw).payload()
                require(event['binding']==budget['binding'] and event['budget_sha256']==owner.budget_hash,'PREDECESSOR_CONTEXT')
                self.predecessors.append(event)
        return self
    def clean(self,op):return {k:v for k,v in op.items() if not k.startswith('_')}


class CaptureDeriver:
    def __init__(self,graph):self.g=graph;self.selection=graph.selected['values'];self._identities={}
    def _op(self,ref,kind):
        value=c.decode('CaptureOperation',self.g.bytes(ref)).payload()
        require(value['kind']==kind and any(value==self.g.clean(x) for x in self.g.ops),'OPERATION_NOT_CAPTURED')
        return value
    def _prior(self,kind):return one([x for x in self.g.predecessors if x['kind']==kind],'PREDECESSOR_UNAVAILABLE')
    def _prior_payload(self,kind):return decode_canonical(self.g.bytes(self._prior(kind)['payload_ref']))
    def _boundary(self,subject):
        values=[x for x in self.g.operations('PROCESS_BOUNDARY') if same_subject(x['data']['subject'],subject)]
        require(values,'PROCESS_BOUNDARY_UNAVAILABLE')
        return values[-1]
    def _parent_samples(self,op):
        body=op['data'];parent=body['parent_subject'];child=body['subject']
        require(parent['pid']==child['parent_pid'] and parent['start_ticks']==child['parent_start_ticks'],
                'PARENT_SUBJECT_MISMATCH')
        samples=[item for item in self.g.operations('PROC_READ') if item['_batch']==op['_batch']
            and item['data']['subject']==parent and item['data']['selector']=='STAT'
            and op['started']['boottime_ns']<=item['started']['boottime_ns']<=item['finished']['boottime_ns']<=op['finished']['boottime_ns']
            and utc(op['started']['utc'])<=utc(item['started']['utc'])<=utc(item['finished']['utc'])<=utc(op['finished']['utc'])]
        stamps={(item['started']['utc'],item['started']['boottime_ns'],item['finished']['utc'],item['finished']['boottime_ns']) for item in samples}
        require(len(stamps)>=2,'PARENT_RAW_SAMPLES_UNAVAILABLE')
        for item in samples:
            raw=self.g.raw(item['data']['raw_ref'],'STAT',parent);actual=parse_stat(raw)
            require(all(actual[key]==parent[key] for key in ('pid','parent_pid','start_ticks')),'PARENT_RAW_IDENTITY')
    def process_identity(self,subject):
        key=(subject['boot_id'],subject['pid'],subject['start_ticks'])
        if key in self._identities:return snapshot(self._identities[key])
        op=self._boundary(subject);self._parent_samples(op);body=op['data'];actual=body['subject']
        for ref in (body['before_stat_ref'],body['after_stat_ref']):
            parsed=parse_stat(self.g.raw(ref,'STAT',actual))
            require(all(parsed[k]==actual[k] for k in ('pid','parent_pid','start_ticks')),'PROC_IDENTITY_MISMATCH')
        status=self.g.raw(body['status_ref'],'STATUS',actual).decode('ascii')
        rows={line.split(':',1)[0]:line.split(':',1)[1].split() for line in status.splitlines() if ':' in line}
        require([int(x) for x in rows['Uid']]==[actual['uid']]*4 and [int(x) for x in rows['Gid']]==[actual['gid']]*4,'PROC_CREDENTIALS')
        namespace=[]
        for row in body['namespace_reads']:
            raw=self.g.raw(row['raw_ref'],'NAMESPACE_LINK',actual).decode('utf-8','strict')
            require(raw==row['link_text'] and raw==row['namespace']+':['+str(row['inode'])+']','NAMESPACE_BYTES')
            namespace.append({k:row[k] for k in ('namespace','link_text','device','inode')})
        mount=self.g.raw(body['mountinfo_ref'],'MOUNTINFO',actual)
        path=self.g.raw(body['exe_link_ref'],'EXE_LINK',actual).decode('utf-8','strict')
        measurements=[x['data'] for x in self.g.operations('FILE_HASH') if x['data']['selected_path']==path
            and x['data']['fd_stat_after']['device']==body['exe_stat']['device'] and x['data']['fd_stat_after']['inode']==body['exe_stat']['inode']]
        require(measurements,'EXECUTABLE_MEASUREMENT_UNAVAILABLE');file=measurements[-1]
        require(file['fd_stat_before']==file['fd_stat_after'] and file['bytes_read']==body['exe_stat']['bytes'],'EXECUTABLE_CHANGED')
        identity={k:actual[k] for k in ('boot_id','pid','start_ticks','parent_pid','uid','gid')}
        identity.update(exe_device=body['exe_stat']['device'],exe_inode=body['exe_stat']['inode'],
            namespace_inventory_ref=self.g.derive('NAMESPACE_INVENTORY',namespace),
            mount_inventory_ref=self.g.derive('MOUNT_INVENTORY',{'mountinfo_utf8':mount.decode('utf-8','strict')}),
            exe_asset={'asset_id':file['asset_id'],'selected_path':path,'bytes':file['bytes_read'],'sha256':file['content_sha256'],
                       'device':body['exe_stat']['device'],'inode':body['exe_stat']['inode']})
        m.validate('ProcessIdentity',identity);self._identities[key]=snapshot(identity)
        return identity
    def _process(self,expected):
        actual=self.process_identity(expected);require(actual==expected,'SELECTED_PROCESS_MISMATCH');return actual
    def _marker(self,kind):
        return one([x for x in self.g.operations('STREAM_MARKER') if x['data']['marker']==kind
                    and x['data']['slot_id']==self.g.selected['slot_id']],'STREAM_MARKER_UNAVAILABLE')
    def _installation_policy(self,selected,spawn):
        # Expected policy is an independently selected static input. Reconstructing
        # this from captured successful calls alone would authenticate no intention.
        policy={key:selected[key] for key in ('abi','handled_fs','rules','targets')}
        raw=canonical_bytes(policy)
        require(digest(raw)==spawn['selected_policy_sha256'],'SELECTED_POLICY_PIN')
        ref=one([ref for ref in self.g.source_refs if ref['artifact_kind']=='CANONICAL_PAYLOAD'
                 and ref['sha256']==spawn['selected_policy_sha256']],'SELECTED_POLICY_SOURCE')
        require(self.g.bytes(ref)==raw,'SELECTED_POLICY_BYTES')
        return raw
    def installation(self,kind):
        selected=self.selection['installation'];spawn=self.g.spawn
        require(spawn is not None and spawn['role']==kind,'SPAWN_REQUIRED')
        self._installation_policy(selected,spawn)
        actual=self._process(selected['process']);require(same_subject(spawn['child'],actual),'SPAWN_PROCESS')
        boundary=self._boundary(actual);parent=self.process_identity(boundary['data']['parent_subject'])
        require(same_subject(spawn['parent'],parent),'SPAWN_PARENT')
        spawn_op=self._op(spawn['spawn_capture_ref'],'SPAWN') if spawn['spawn_capture_ref']['artifact_kind']=='CANONICAL_PAYLOAD' else None
        if spawn_op is None:
            matches=[x for x in self.g.operations('SPAWN') if x['_batch']==spawn['spawn_capture_ref'] and x['operation_index']==spawn['spawn_operation_index']]
            spawn_op=self.g.clean(one(matches,'SPAWN_OPERATION'))
        observed=spawn_op['data'];require(observed['paused_child']==spawn['child'] and observed['parent']==spawn['parent']
            and observed['descriptor_bindings']==spawn['descriptor_bindings'] and observed['selected_policy_sha256']==spawn['selected_policy_sha256']
            and observed['selected_component_sha256']==spawn['component_sha256'] and observed['selected_executable_asset_id']==spawn['selected_executable_asset_id']
            and observed['result']=='SPAWNED_AND_PAUSED','SPAWN_OBSERVATION')
        fds=one([x for x in self.g.operations('FD_INVENTORY') if same_subject(x['data']['subject'],actual)
                 and x['data']['paused_boundary_id']==spawn['spawn_id']],'INITIAL_FD_INVENTORY')
        descriptors=[]
        for row in fds['data']['entries']:
            self.g.raw(row['link_ref'],'FD_LINK');info=self.g.raw(row['fdinfo_ref'],'FDINFO').decode('ascii')
            flags=one([int(x.split(':',1)[1],8) for x in info.splitlines() if x.startswith('flags:')],'FDINFO_FLAGS')
            d=row['descriptor'];require(row['fstat_return']==row['fstat_errno']==0 and d['device']==row['stat']['device'] and d['inode']==row['stat']['inode']
                and d['access_flags']==flags&~os.O_CLOEXEC and d['close_on_exec']==bool(flags&os.O_CLOEXEC),'DESCRIPTOR_BYTES')
            descriptors.append(d)
        require(descriptors==selected['descriptors'],'SELECTED_DESCRIPTOR_MISMATCH')
        threads=[{'tid':x['pid'],'start_ticks':x['start_ticks']} for x in (parse_stat(self.g.raw(r,'TASK_STAT')) for r in boundary['data']['task_stat_refs'])]
        require(threads==[{'tid':actual['pid'],'start_ticks':actual['start_ticks']}],'INSTALL_SINGLE_THREAD')
        calls=[x for x in self.g.operations('INSTALL_CALL') if same_subject(x['data']['subject'],actual)]
        require(calls and all(x['data']['abi_layout_sha256']==digest(canonical_bytes(ABI_LAYOUT)) for x in calls),'ABI_LAYOUT_PIN')
        expected=['ABI_QUERY','RULESET_CREATE']+['ADD_PATH_RULE']*len(selected['rules'])+['PR_SET_NO_NEW_PRIVS','RESTRICT_SELF','PR_GET_NO_NEW_PRIVS']
        require([x['data']['operation'] for x in calls]==expected,'INSTALL_CALL_ORDER')
        require(fds['finished']['boottime_ns']<=calls[0]['started']['boottime_ns'],'INSTALL_FD_ORDER')
        query,create=calls[:2];ruleset=create['data']['return_value'];require(ruleset>=0 and query['data']['return_value']==selected['abi'],'INSTALL_ABI')
        for call in calls:
            data=call['data'];arguments=canonical_bytes(data['arguments'])
            matches=[x for x in self.g.manifests if x['source_selector']=='NATIVE_INSTALL_ARGUMENTS' and x['subject']==data['subject']
                     and x['started']==call['started'] and x['finished']==call['finished'] and x['raw_sha256']==digest(arguments)]
            require(matches and all(self.g.bytes(x['blob_ref'])==arguments for x in matches),'INSTALL_NATIVE_ARGUMENT_CAPTURE')
        require(calls[-2]['data']['arguments']=={'ruleset_fd':ruleset,'flags':0},'INSTALL_RESTRICT_ARGUMENTS')
        require(all(x['data']['errno']==0 for x in calls) and all(x['data']['return_value']==0 for x in calls[2:-1]) and calls[-1]['data']['return_value']==1,'INSTALL_CALL_FAILED')
        require(create['data']['arguments']=={'handled_fs':selected['handled_fs'],'handled_net':0,'size':16,'attr_bytes_hex':struct.pack('<QQ',selected['handled_fs'],0).hex(),'flags':0},'INSTALL_CREATE_ARGUMENTS')
        targets=[];rules=[];syscalls=[]
        mapping={'ABI_QUERY':('LANDLOCK_CREATE_RULESET',{'mode':'ABI_QUERY'}),'RULESET_CREATE':('LANDLOCK_CREATE_RULESET',{'mode':'CREATE','handled_fs':selected['handled_fs']}),
            'PR_SET_NO_NEW_PRIVS':('PR_SET_NO_NEW_PRIVS',{'no_new_privs':1}),'RESTRICT_SELF':('LANDLOCK_RESTRICT_SELF',{'ruleset_fd':ruleset,'flags':0})}
        opens=[x for x in self.g.operations('RULE_TARGET_OPEN') if x['_subject']==calls[0]['_subject']]
        for call,rule in zip(calls[2:-3],selected['rules']):
            arg=call['data']['arguments'];opened=one([x for x in opens if x['data']['returned_fd']==arg['parent_fd'] and x['data']['target_id']==rule['target_id']],'RULE_TARGET_OPEN')
            target=opened['data'];require(opened['operation_index']<call['operation_index'] and opened['_batch']==call['_batch']
                and target['access_mask']==rule['rights'] and target['open_flags']==os.O_PATH|os.O_CLOEXEC|os.O_NOFOLLOW,'INSTALL_TARGET_ORDER')
            require(target['errno']==0 and target['stat'] is not None and arg=={'ruleset_fd':ruleset,'rule_type':1,'allowed_access':rule['rights'],
                'parent_fd':target['returned_fd'],'attr_bytes_hex':struct.pack('<Qi',rule['rights'],target['returned_fd']).hex(),'flags':0},'INSTALL_ADD_ARGUMENTS')
            path=self.g.raw(target['resolved_link_ref'],'FD_LINK').decode('utf-8','strict')
            targets.append({'target_id':target['target_id'],'device':target['stat']['device'],'inode':target['stat']['inode'],'resolved_path':path})
            rules.append({'target_id':target['target_id'],'rights':arg['allowed_access']})
            mapping[id(call)]=('LANDLOCK_ADD_RULE',{'ruleset_fd':ruleset,'target':targets[-1],'rights':arg['allowed_access']})
        require(targets==selected['targets'] and rules==selected['rules'],'INSTALL_TARGET_SELECTION')
        for call in calls[:-1]:
            name=call['data']['operation'];operation,args=mapping[id(call)] if name=='ADD_PATH_RULE' else mapping[name]
            ref=self.g.derive('INSTALL_ARGUMENTS',args)
            syscalls.append({'operation':operation,'arguments_ref':ref,'return_value':call['data']['return_value'],'errno':0,'observed':call['finished']})
        self.g.derive('PROC_IDENTITY',{'process':actual,'parent':parent,'threads':threads,'observed_start':boundary['started'],'observed_end':boundary['finished']})
        self.g.derive('DESCRIPTOR_INVENTORY',{'process':actual,'descriptors':descriptors,'observed':fds['finished']})
        self.g.derive('INSTALL_ARGUMENTS',{'process':actual,'no_new_privs':1,'observed':calls[-1]['finished']})
        return {'process_identity':actual,'threads':threads,'initial_descriptors':descriptors,'expected_descriptor_plan_ref':selected['descriptor_plan_ref'],
            'normalized_rules_ref':self.g.derive('NORMALIZED_RULES',rules),'rule_target_inventory_ref':self.g.derive('RULE_TARGET_INVENTORY',targets),
            'landlock_abi':query['data']['return_value'],'handled_fs':create['data']['arguments']['handled_fs'],'syscalls':syscalls,
            'no_new_privs_readback':1,'parent_installation_record_id':self._prior('RUNNER_INSTALL')['record_id'] if kind=='MODEL_INSTALL' else None}

    def calibration_case(self,expectation):
        receiver=self._process(self.selection['controller']);expected=self._process(self.selection['calibration']['expected_peer'])
        count=2 if expectation['case_kind']=='BAD_SEQUENCE' else 1;exchanges=[];identity=None;endpoint_ids=set();senders=[]
        for index in range(1,count+1):
            exchange_id=expectation['case_id']+'-exchange-'+str(index)
            send=one([x for x in self.g.operations('SEND') if x['data']['exchange_id']==exchange_id],'CALIBRATION_SEND')
            recv=one([x for x in self.g.operations('RECV') if x['data']['exchange_id']==exchange_id],'CALIBRATION_RECV')
            sent,received=send['data'],recv['data'];sender=self.process_identity(sent['sender']);senders.append(sender)
            require(same_subject(received['receiver'],receiver),'RECEIVER_IDENTITY')
            app=self.g.raw(sent['application_ref'],'APPLICATION_PACKET',sent['sender']);frame=self.g.raw(sent['frame_ref'],'WIRE_FRAME',sent['sender'])
            data=self.g.raw(received['data_ref'],'WIRE_FRAME',received['receiver'])
            require(frame==data and sent['return_value']==len(frame)>0 and received['return_value']==len(data)>0
                and sent['errno']==received['errno']==0,'CALIBRATION_WIRE_BYTES')
            ancillary=decode_canonical(self.g.raw(received['ancillary_raw_ref'],'ANCILLARY_BYTES',received['receiver']))
            credentials=[];rights=[]
            for row in ancillary:
                require(set(row)=={'level','type','hex'},'ANCILLARY_SHAPE');raw=bytes.fromhex(row['hex'])
                if row['level']==socket.SOL_SOCKET and row['type']==socket.SCM_CREDENTIALS:
                    require(len(raw)==12,'CREDENTIAL_BYTES');credentials.append(dict(zip(('pid','uid','gid'),struct.unpack('3i',raw))))
                elif row['level']==socket.SOL_SOCKET and row['type']==socket.SCM_RIGHTS:
                    require(len(raw)%4==0,'RIGHTS_BYTES');rights.extend(struct.unpack('='+'i'*(len(raw)//4),raw))
                else:raise ContractError('CALIBRATION_UNKNOWN_ANCILLARY')
            require((one(credentials,'CREDENTIAL_AMBIGUITY') if credentials else None)==received['ucred'],'CREDENTIAL_CAPTURE_MISMATCH')
            require(rights==[x['fd'] for x in received['delivered_descriptors']] and len(rights)==len(set(rights)),'RIGHTS_CAPTURE_MISMATCH')
            gates=[x for x in self.g.operations('VERIFIER_GATE') if x['data']['exchange_id']==exchange_id]
            verdict=one([x for x in gates if x['data']['gate']=='VERDICT'],'VERDICT_UNAVAILABLE')
            exposure=one([x for x in gates if x['data']['gate']=='EXPOSURE'],'EXPOSURE_UNAVAILABLE')
            require(all(x['_batch']==recv['_batch'] for x in gates) and verdict['operation_index']<exposure['operation_index'],'VERIFIER_ORDER')
            v=verdict['data'];e=exposure['data'];require(all(v[k]==e[k] for k in v if k!='gate'),'VERIFIER_EXPOSURE_MISMATCH')
            require(v['receiver_component_sha256']==expectation['receiver_component_sha256'],'RECEIVER_COMPONENT')
            ids=(v['channel_instance_id'],v['instance_id'],v['key_operation_id'])
            require(identity is None or identity==ids,'REPLAY_INSTANCE_CHANGED');identity=ids
            packet=decode_canonical(app);require(set(packet)=={'body','mac'} and set(packet['body'])=={'channel_id','sequence','method','value'},'CALIBRATION_PACKET')
            body=packet['body'];fixture_raw=self.g.bytes(expectation['fixture_ref'])
            require(body['method']=='PUBLIC_INERT' and body['value']==decode_canonical(fixture_raw),'CALIBRATION_PUBLIC_VALUE')
            key=public_fixture_key(fixture_raw,v['key_operation_id'])
            mac_valid=type(packet['mac']) is str and hmac.compare_digest(packet['mac'],hmac.new(key,canonical_bytes(body),hashlib.sha256).hexdigest())
            frame_valid=len(frame)>8 and struct.unpack('!II',frame[:8])==(len(app),0) and frame[8:]==app
            channel_matches=body['channel_id']==v['channel_instance_id']
            failed=[x for x in gates if x['data']['outcome']=='CHECK_FAIL']
            stage=one(failed,'REJECTION_GATE')['data']['gate'] if failed else 'NONE'
            expected_gates=['ANCILLARY','PEER_CREDENTIALS','FRAME','MAC','CHANNEL_ID','SEQUENCE']
            reached=[x['data']['gate'] for x in gates if x['data']['gate'] not in ('VERDICT','EXPOSURE')]
            require(reached==expected_gates[:expected_gates.index(stage)+1] if stage!='NONE' else reached==expected_gates,'VERIFIER_GATE_ORDER')
            trace={'frame_valid':frame_valid,'mac_valid':mac_valid,'channel_matches':channel_matches,'packet_sequence':body['sequence'],
                'verdict':v['outcome'],'rejection_stage':stage,'seq_before':v['sequence_before'],'seq_after':v['sequence_after'],
                'closed_before':gates[0]['data']['receiver_closed'],'closed_after':v['receiver_closed'],'handler_before':v['handler_entries_before'],'handler_after':v['handler_entries_after'],
                'instance_id':v['instance_id'],'channel_instance_id':v['channel_instance_id'],'key_id':v['key_operation_id'],
                'exchange_id':exchange_id,'verdict_operation_index':verdict['operation_index'],'exposure_operation_index':exposure['operation_index'],
                'verdict_observed':verdict['finished'],'exposure_observed':exposure['finished']}
            closes=[]
            for descriptor in received['delivered_descriptors']:
                close=one([x for x in self.g.operations('CLOSE') if x['_batch']==recv['_batch'] and x['data']['exchange_id']==exchange_id
                           and x['data']['descriptor']==descriptor],'DELIVERED_CLOSE_UNAVAILABLE')
                require(close['data']['return_value']==close['data']['errno']==0 and close['operation_index']<verdict['operation_index'],'DELIVERED_CLOSE_ORDER')
                raw={'descriptor':descriptor,'return_value':0,'errno':0,'observed':close['finished'],'exchange_id':exchange_id,'operation_index':close['operation_index']}
                closes.append({'descriptor':descriptor,'close_return':0,'close_errno':0,'closed_at':close['finished'],'raw_close_ref':self.g.derive('DESCRIPTOR_CLOSES',raw)})
            normalized_recv={'frames_hex':data.hex(),'receiver':receiver,'actual_ucred':received['ucred'],'return_value':received['return_value'],
                'errno':received['errno'],'msg_trunc':bool(received['msg_flags']&socket.MSG_TRUNC),'msg_ctrunc':bool(received['msg_flags']&socket.MSG_CTRUNC),
                'delivered_fds':received['delivered_descriptors']}
            exchanges.append({'exchange_index':index,'observed_start':send['started'],'observed_end':exposure['finished'],'actual_sender_identity':sender,
                'sent_record_ref':self.g.derive('IPC_SEND',{'application_hex':app.hex(),'frames_hex':frame.hex(),'sender':sender,'return_value':sent['return_value'],'errno':sent['errno']}),
                'recv_record_ref':self.g.derive('IPC_RECEIVE',normalized_recv),'sent_application_packet_sha256':digest(app),'sent_frames_sha256':digest(frame),
                'received_frames_sha256':digest(data),'send_return':sent['return_value'],'send_errno':sent['errno'],'recv_return':received['return_value'],'recv_errno':received['errno'],
                'actual_ucred':received['ucred'],'msg_trunc':normalized_recv['msg_trunc'],'msg_ctrunc':normalized_recv['msg_ctrunc'],
                'recv_seq_before':v['sequence_before'],'recv_seq_after':v['sequence_after'],'receiver_closed_before':gates[0]['data']['receiver_closed'],'receiver_closed_after':v['receiver_closed'],
                'verdict':v['outcome'],'rejection_stage':stage,'verifier_trace_ref':self.g.derive('VERIFIER_TRACE',trace),'handler_entries_before':0,'handler_entries_after':0,
                'delivered_fds':received['delivered_descriptors'],'close_outcomes':closes})
            endpoint_ids.update(x['socket_descriptor']['selected_target_id'] for x in (sent,received))
        unique_senders=[]
        for sender in senders:
            if sender not in unique_senders:unique_senders.append(sender)
        self.g.derive('PROC_IDENTITY',{'receiver':receiver,'expected_peer':expected,'senders':unique_senders,
            'live_pids':sorted(set(x['pid'] for x in (receiver,expected,*unique_senders))),'observed':recv['finished']})
        return {'case_id':expectation['case_id'],'case_kind':expectation['case_kind'],'slot_id':expectation['slot_id'],'fixture_ref':expectation['fixture_ref'],
            'receiver_identity':receiver,'receiver_component_sha256':expectation['receiver_component_sha256'],'expected_peer_identity':expected,
            'channel_instance_id':identity[0],'verifier_instance_id':identity[1],'channel_object_ids':sorted(endpoint_ids),'public_fixture_key_id':identity[2],'exchanges':exchanges}

    def derive_payload(self,kind):
        g=self.g;s=self.selection
        if kind in ('RUNNER_INSTALL','MODEL_INSTALL'):return self.installation(kind)
        if kind=='CALIBRATION_CASE':
            return self.calibration_case(one([x for x in g.owner.plan['calibration_plan'] if x['slot_id']==g.selected['slot_id']],'CALIBRATION_PLAN'))
        if kind in ('SETUP_BEGIN','CALIBRATION_BEGIN'):
            marker=self._marker(kind);process=self._process(s['controller']);g.derive('PROC_IDENTITY',process)
            if kind=='SETUP_BEGIN':return {'coverage_plan_sha256':g.owner.budget['coverage_plan_sha256'],'producer_identity':process,'budget_sha256':g.owner.budget_hash}
            require(not any(x['data']['random_source_call_succeeded'] for x in g.operations('ENDPOINT_CREATE')),'FINAL_KEY_CREATED_EARLY')
            # Absence of private reads is a selected-phase prerequisite, never inferred from capture silence.
            require(g.owner.phase_guard(kind,observed=marker['finished'],now=g.now) is None,'PUBLIC_CALIBRATION_PHASE_UNAVAILABLE')
            return {'receiver_identity':process,'receiver_component_sha256':s['calibration']['receiver_component_sha256'],
                'planned_case_ids':[x['case_id'] for x in g.owner.plan['calibration_plan']],'final_key_created':False,'private_documents_opened':False}
        if kind=='ASSET_BINDINGS':
            rows=[];measurements=g.operations('FILE_HASH')
            for selected in s['assets']:
                op=one([x for x in measurements if x['data']['asset_id']==selected['asset_id']],'ASSET_MEASUREMENT')
                f=op['data'];require(f['fd_stat_before']==f['fd_stat_after'],'ASSET_CHANGED')
                # The captured statvfs-backed read-only evidence is separately source-bound.
                require(f['mount_read_only_evidence_ref'] in g.source_refs,'ASSET_MOUNT_SOURCE')
                row={'asset_id':f['asset_id'],'path':f['selected_path'],'bytes':f['bytes_read'],'sha256':f['content_sha256'],
                     'device':f['fd_stat_after']['device'],'inode':f['fd_stat_after']['inode'],'read_only':True}
                require(row==selected,'ASSET_SELECTION');rows.append(row)
            return {'selected_asset_manifest_sha256':s['asset_manifest_sha256'],'actual_file_inventory_ref':g.derive('ASSET_INVENTORY',rows),
                'hash_scan_started':min((x['started'] for x in measurements),key=lambda x:x['boottime_ns']),
                'hash_scan_completed':max((x['finished'] for x in measurements),key=lambda x:x['boottime_ns'])}
        if kind=='FINAL_CHANNEL_CREATED':
            op=one(g.operations('ENDPOINT_CREATE'),'CHANNEL_CREATION');d=op['data'];owner=self.process_identity(d['owner'])
            require(d['random_source_call_succeeded'] and not d['key_material_recorded'],'FINAL_KEY_OPERATION')
            actual={'channel_id':d['channel_id'],'endpoint_ids':[x['selected_target_id'] for x in d['endpoints']],
                    'owner':owner,'key_operation_id':d['key_operation_id'],'created_at':op['finished']}
            require(actual==s['channel'],'CHANNEL_SELECTION')
            return {'channel_id':d['channel_id'],'endpoint_inventory_ref':g.derive('DESCRIPTOR_INVENTORY',actual),
                'key_generation_operation_id':d['key_operation_id'],'calibration_retired_record_id':self._prior('CALIBRATION_RETIRED')['record_id'],'key_material_recorded':False}
        if kind=='CALIBRATION_RETIRED':
            selected=s['calibration'];retired=[]
            for expected in selected['temporary_actors']:
                op=one([x for x in g.operations('CHILD_RETIREMENT') if same_subject(x['data']['subject'],expected)],'RETIREMENT_OBSERVATION')
                d=op['data'];require(d['wait_result'] in ('EXITED','SIGNALED') and d['wait_status'] is not None and not d['remaining_live_subjects'],'RETIREMENT_UNCONFIRMED')
                retired.append(self._process(expected))
            endpoints=[]
            cases=sorted([x for x in g.predecessors if x['kind']=='CALIBRATION_CASE'],key=lambda x:x['sequence'])
            require(len(cases)==8,'CALIBRATION_RETIREMENT_PREFIX')
            for event in cases:
                payload=decode_canonical(g.bytes(event['payload_ref']))
                for exchange in payload['exchanges']:
                    delivered=exchange['delivered_fds'];closed=exchange['close_outcomes']
                    require(len(delivered)==len(closed) and sorted(canonical_bytes(x) for x in delivered)==sorted(canonical_bytes(x['descriptor']) for x in closed)
                        and all(x['close_return']==x['close_errno']==0 for x in closed),'DELIVERED_RETIREMENT_INCOMPLETE')
                for target in payload['channel_object_ids']:
                    close=one([x for x in g.operations('CLOSE') if x['data']['descriptor']['selected_target_id']==target
                               and x['data']['return_value']==x['data']['errno']==0],'ENDPOINT_RETIREMENT')
                    endpoints.append(target)
            observed=max((x['finished'] for x in g.operations('CHILD_RETIREMENT')),key=lambda x:x['boottime_ns'])
            require(g.owner.phase_guard(kind,observed=observed,now=g.now) is None,'PUBLIC_CALIBRATION_PHASE_UNAVAILABLE')
            retirement={'challenger':self._process(selected['foreign_sender']),'retired_pids':[x['pid'] for x in retired],
                'retired_identities':retired,'remaining_descendants':[],'unclosed_delivered_fds':[],'observed':observed}
            require(set(retirement['retired_pids'])==set(selected['retired_pids']),'RETIREMENT_SET')
            return {'completed_case_ids':[decode_canonical(g.bytes(x['payload_ref']))['case_id'] for x in cases],
                'endpoint_retirement_ref':g.derive('ENDPOINT_RETIREMENT',{'closed_endpoint_ids':endpoints,'observed':observed}),
                'challenger_identity':retirement['challenger'],'process_retirement_ref':g.derive('PROCESS_RETIREMENT',retirement),
                'remaining_challenger_descendants':0,'unclosed_delivered_fds':0,'final_key_created':False}
        if kind=='MODEL_POST_EXEC':
            selected=s['post_exec'];actual=self._process(selected['process']);parent=self._process(selected['parent'])
            before=self._prior_payload('MODEL_INSTALL')['process_identity'];op=one(g.operations('LISTENER_READ'),'LISTENER_UNAVAILABLE');d=op['data']
            require(same_subject(d['subject'],actual),'LISTENER_PROCESS');table=g.raw(d['tcp_table_ref'],'NET_TCP').decode('ascii')
            rows=[line.split() for line in table.splitlines()[1:] if line.strip()]
            require(any(len(row)>9 and row[3]=='0A' and row[1]==f"0100007F:{d['port']:04X}" and int(row[9])==d['socket_descriptor']['inode'] for row in rows),'LISTENER_TABLE')
            fd=self._op(d['fd_inventory_ref'],'FD_INVENTORY')
            require(d['socket_descriptor'] in [x['descriptor'] for x in fd['data']['entries']],'LISTENER_FD_OWNERSHIP')
            listener={'process':actual,'address':d['address'],'port':d['port'],'socket_inode':d['socket_descriptor']['inode'],'observed':op['finished']}
            require(all(listener[k]==selected['listener'][k] for k in ('process','address','port','socket_inode')),'LISTENER_SELECTION')
            path=actual['exe_asset']['selected_path'];require(path==selected['exe_path'],'EXEC_PATH')
            g.derive('PROC_IDENTITY',{'process':actual,'parent':parent,'exe_path':path,'observed':op['finished']})
            return {'wrapper_installation_record_id':self._prior('MODEL_INSTALL')['record_id'],'actual_server_identity':actual,
                'asset_binding_record_id':self._prior('ASSET_BINDINGS')['record_id'],'owned_listener_ref':g.derive('LISTENER_IDENTITY',listener),
                'wrapper_to_exec_identity_ref':g.derive('EXEC_LINEAGE',{'before':before,'after':actual,'parent':parent,'exe_path':path,'observed':op['finished']})}
        if kind=='FINAL_PEER_BOUND':
            recv=one(g.operations('RECV'),'FIRST_PEER_RECEIVE');d=recv['data'];g.raw(d['data_ref'],'WIRE_FRAME')
            gates=[x for x in g.operations('VERIFIER_GATE') if x['data']['exchange_id']==d['exchange_id']]
            accepted=one([x for x in gates if x['data']['gate']=='EXPOSURE' and x['data']['outcome']=='ACCEPTED_INERT'],'FIRST_PEER_EXPOSURE')
            require(any(x['data']['gate']=='MAC' and x['data']['outcome']=='CHECK_PASS' for x in gates),'FIRST_PEER_MAC_UNOBSERVED')
            runner=self._prior_payload('RUNNER_INSTALL')['process_identity'];actual=self._process(runner)
            require(d['ucred']=={k:actual[k] for k in ('pid','uid','gid')} and not d['delivered_descriptors'] and d['msg_flags']==0,'FIRST_PEER_CREDENTIALS')
            inventory=one([x for x in g.operations('FD_INVENTORY') if same_subject(x['data']['subject'],actual)],'CURRENT_PEER_FD_INVENTORY')
            installed=self._prior_payload('RUNNER_INSTALL')['initial_descriptors']
            candidates=[x['descriptor'] for x in inventory['data']['entries'] if x['descriptor']['object_type']=='SOCKET' and x['descriptor'] in installed]
            descriptor=one(candidates,'CURRENT_PEER_DESCRIPTOR');owner=actual;v=accepted['data']
            require(v['sequence_before']==0 and v['sequence_after']==1 and v['channel_instance_id']==s['channel']['channel_id'],'FIRST_PEER_SEQUENCE_CHANNEL')
            packet={'channel_id':v['channel_instance_id'],'endpoint_id':descriptor['selected_target_id'],'owner':owner,'ucred':[d['ucred'][k] for k in ('pid','uid','gid')],
                'mac_valid':True,'sequence':v['sequence_after'],'received_at':recv['finished'],'key_operation_id':v['key_operation_id']}
            ref=g.derive('IPC_RECEIVE',packet)
            peer=g.derive('PROC_IDENTITY',{'process':actual,'endpoint_id':descriptor['selected_target_id'],'descriptor':descriptor,'observed':self._boundary(actual)['finished']})
            require(ref==s['peer']['first_packet_ref'] and peer==s['peer']['current_peer_ref'],'PEER_SELECTION')
            return {'channel_created_record_id':self._prior('FINAL_CHANNEL_CREATED')['record_id'],'channel_id':v['channel_instance_id'],'actual_peer_identity':actual,
                'first_packet_ref':ref,'actual_ucred':packet['ucred'],'model_post_exec_record_id':self._prior('MODEL_POST_EXEC')['record_id']}
        if kind=='POLICY_ARGUMENT':
            marker=self._marker(kind);ref=marker['data']['source_argument_ref'];require(ref==s['source_argument_ref'] and ref in g.source_refs,'SOURCE_ARGUMENT_SELECTION')
            raw=g.bytes(ref);argument=decode_canonical(raw)
            expected={'claim':'TRUSTED_INSTALLATION_AND_INHERITANCE','non_forwarding_status':'ASSUMPTION_BOUND_NON_FORWARDING',
                'unsupported_routes':g.owner.plan['unsupported_routes'],'every_task_post_exec_probes_claimed':False}
            require(argument==expected,'SOURCE_ARGUMENT_SCOPE');derived=g.derive('SOURCE_ARGUMENT',argument);require(derived==ref,'SOURCE_ARGUMENT_BYTES')
            return {'installation_record_ids':[self._prior(k)['record_id'] for k in ('RUNNER_INSTALL','MODEL_INSTALL')],
                'post_exec_record_id':self._prior('MODEL_POST_EXEC')['record_id'],'source_argument_ref':derived,**expected}
        if kind=='SETUP_SEAL':
            marker=self._marker(kind);events=sorted(g.predecessors,key=lambda x:x['sequence'])
            require([x['sequence'] for x in events]==list(range(1,19)),'SEAL_PREFIX')
            entries=[{'sequence':x['sequence'],'record_id':x['record_id'],'record_sha256':digest(canonical_bytes(x))} for x in events]
            return {'entries':entries,'covered_slot_ids':[x['slot_id'] for x in events],
                'previous_head_sha256':entries[-1]['record_sha256'],'previous_record_count':18,'unsupported_routes':g.owner.plan['unsupported_routes']}
        raise DependencyUnavailable('failure_payload_requires_authenticated_cleanup_diagnosis')


PAYLOAD_TYPES={'SETUP_BEGIN':'SetupBeginPayload','CALIBRATION_BEGIN':'CalibrationBeginPayload','CALIBRATION_CASE':'CalibrationCasePayload',
 'CALIBRATION_RETIRED':'CalibrationRetiredPayload','FINAL_CHANNEL_CREATED':'FinalChannelCreatedPayload','RUNNER_INSTALL':'InstallationPayload',
 'MODEL_INSTALL':'InstallationPayload','ASSET_BINDINGS':'AssetBindingsPayload','MODEL_POST_EXEC':'PostExecPayload','FINAL_PEER_BOUND':'FinalPeerPayload',
 'POLICY_ARGUMENT':'PolicyArgumentPayload','SETUP_SEAL':'SetupSealPayload','FAILURE':'FailurePayload'}


class AuthenticatedDecoder:
    def __init__(self,*,evidence,authenticator,appointment,budget,plan,sink,component_sha256,format_sha256,
                 accepted_event,phase_guard,event_inputs=None,producer_inputs=None):
        require((event_inputs is None)!=(producer_inputs is None),'DECODER_CONTEXT_MODE')
        require(callable(accepted_event) and callable(phase_guard),'DECODER_DEPENDENCY')
        self.evidence,self.auth,self.sink=evidence,authenticator,sink
        self.appointment=m.validate('Appointment',appointment).payload();self.budget=m.validate('SetupBudget',budget).payload()
        self.plan=m.validate('CoveragePlan',plan).payload();self.budget_hash=digest(canonical_bytes(self.budget))
        self.component,self.format=component_sha256,format_sha256
        self.accepted_event,self.phase_guard=accepted_event,phase_guard
        self.event_inputs=snapshot(event_inputs) if event_inputs else None
        self.producer_inputs=None if producer_inputs is None else ProducerInputs(
            runtime_selection=snapshot(producer_inputs.runtime_selection),selected_values=snapshot(producer_inputs.selected_values),
            selected_source_refs=tuple(snapshot(list(producer_inputs.selected_source_refs))),
            raw_blob_manifests=tuple(snapshot(list(producer_inputs.raw_blob_manifests))),
            spawn_selection=snapshot(producer_inputs.spawn_selection) if producer_inputs.spawn_selection else None)
        self._artifacts=();self._bindings=()
    @property
    def derived_artifacts(self):return tuple((snapshot(ref),raw) for ref,raw in self._artifacts)
    @property
    def derived_bindings(self):return tuple(snapshot(x) for x in self._bindings)
    def decode_actual(self,captures:tuple[c.AuthenticatedMethodObject,...],*,selection:c.RuntimeSelectedValues,
                      decoder_component_sha256:str,decoder_format_sha256:str,now:m.Stamp)->tuple[c.DecodeBinding,bytes]:
        self._artifacts=();self._bindings=();now=m.validate('Stamp',now).payload()
        require(decoder_component_sha256==self.component and decoder_format_sha256==self.format,'DECODER_EXTERNAL_PIN')
        captures=tuple(snapshot(list(captures)));selection=c.validate('RuntimeSelectedValues',selection).payload()
        graph=AuthenticatedGraph(owner=self,now=now).prepare(captures,selection)
        decoded=now;existing=[]
        if graph.inputs:
            existing=[graph.authenticated(pair,'DecodeBinding','RUNTIME_DECODE_BINDING') for pair in graph.inputs['decode_objects']]
            decoded=existing[0]['decoded']
            require(all(x['decoded']==decoded for x in existing) and self.budget['started']['boottime_ns']<=decoded['boottime_ns']<=now['boottime_ns']
                and utc(self.budget['started']['utc'])<=utc(decoded['utc'])<=utc(now['utc']),'DECODE_ORIGINAL_STAMP')
        kind=selection['event_kind'];payload=CaptureDeriver(graph).derive_payload(kind)
        raw=m.validate(PAYLOAD_TYPES[kind],payload).raw;primary=graph.derive('CANONICAL_PAYLOAD',payload)
        refs=[pair['object_ref'] for pair in captures];envelopes=[pair['envelope_ref'] for pair in captures]
        require(len(graph.derived)+2<=64,'NORMALIZED_GRAPH_BOUND')
        bindings=[]
        for ref,_ in graph.derived:
            value={'format':'forex.runtime-decode-binding/2','binding':self.budget['binding'],'budget_sha256':self.budget_hash,
                'event_kind':kind,'decoder_component_sha256':self.component,'decoder_format_sha256':self.format,'capture_refs':refs,
                'capture_envelope_refs':envelopes,'selected_input_refs':graph.source_refs,'normalized_ref':ref,'normalized_artifact_kind':ref['artifact_kind'],'decoded':decoded}
            c.validate('DecodeBinding',value);bindings.append(value)
        if existing:
            require(sorted(canonical_bytes(x) for x in existing)==sorted(canonical_bytes(x) for x in bindings),'REDECODE_BINDING_SET')
            for ref,value in graph.derived:require(graph.bytes(ref)==value,'REDECODE_ARTIFACT_BYTES')
        self._artifacts=tuple(graph.derived);self._bindings=tuple(bindings)
        return one([x for x in bindings if x['normalized_ref']==primary],'PRIMARY_DECODE'),raw
