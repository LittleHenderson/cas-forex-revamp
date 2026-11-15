"""Fixed source-completion client factory. No keys, roots or services created.

External authorizer/reviewer signatures appoint the records. Actual source-test
authority is checked through a fresh selected current-register endpoint. No
private-release, method setup, model service or arbitrary import route exists.
"""
from threading import RLock
from cas_forex_operational_contracts import common, protected as pr, completion as co, method
from cas_forex_authority.authentication import Ed25519Verifier
from .selection_provider import SelectionProvider, SchemaRoute, PUBLISHER_ROUTES, same, call_none
from .protected_registry import ProtectedFiles, ProtectedResolver
from .completion_verifier import CompletionVerifier, FrameworkParser
from .gate_adapters import OriginalClockSchema
from .source_test_clock import SourceTestClockSchema
from .completion_transport import LocalCompletionClient, closed

CONFIG_FORMAT='forex.source-completion-client-bindings/1'
CONFIG_FIELDS={'format','local_principal_id','publisher_selection','selection_signature_hex','authorizer_public_sha256',
    'source_manifest_sha256','completion_material_sha256','verifier_id','verifier_component_sha256',
    'observer_publisher_id','custody_publisher_id','schema_routes','parser_routes',
    'current_endpoint','registry_endpoint','observer_endpoint','custody_endpoint'}
COMPLETION_TYPES={'CompletionSelection2','CommandPin','ParserPin','CollectionInventory','SourceInventory','TestStream2',
    'ProcessCapture2','GroupReport2','CompletionObservation2','SourceTestReport2','CompletionReceipt2',
    'PythonFrameworkReport2','NodeTapReport1','NodeVersionReport1','TestDiscoveryReport'}
PARSER_ENTRYPOINTS={'custody-strict-framework-v1','cas_forex_measurement.completion.parse_python',
    'cas_forex_measurement.completion.parse_flat_tap','cas_forex_measurement.completion.node_version_report'}
PUBLISH_ROUTES={
    'TEST_STREAM':('test-stream','COMPLETION_OBSERVER'),
    'TEST_PROCESS_CAPTURE':('test-process-capture','COMPLETION_OBSERVER'),
    'TEST_GROUP_REPORT':('test-group-report','COMPLETION_OBSERVER'),
    'TEST_DISCOVERY_REPORT':('test-discovery-report','COMPLETION_OBSERVER'),
    'TEST_FRAMEWORK_REPORT':('test-framework-report','COMPLETION_OBSERVER'),
    'SOURCE_TEST_OBSERVATION':('source-test-observation','COMPLETION_OBSERVER'),
    'SOURCE_TEST_COMPLETION':('source-test-completion','COMPLETION_OBSERVER'),
    'SOURCE_TEST_REPORT':('original-source-test-report','CUSTODY')}
require=common.require


def _snapshot(value):return common.decode_canonical(common.canonical_bytes(value,limit=common.MAX_GRAPH),limit=common.MAX_GRAPH)


def _pin(value):
    require(type(value) is str and len(value)==64 and all(x in '0123456789abcdef' for x in value),'SOURCE_PIN')
    return value


def _hex(value, length=None):
    require(type(value) is str and len(value)%2==0 and all(x in '0123456789abcdef' for x in value),'SOURCE_HEX')
    raw=bytes.fromhex(value)
    require(length is None or len(raw)==length,'SOURCE_HEX_LENGTH');return raw


def selected_schema_routes(rows):
    require(type(rows) is list and 0<len(rows)<=64,'SOURCE_SCHEMA_ROUTES')
    result={}
    for row in rows:
        closed(row,{'schema_sha256','namespace','type_name','maximum_stream_bytes'},'SOURCE_SCHEMA_ROUTE')
        pin=_pin(row['schema_sha256']);require(pin not in result,'SOURCE_SCHEMA_DUPLICATE')
        maximum=row['maximum_stream_bytes']
        require(maximum is None or type(maximum) is int and 0<maximum<=common.MAX_OBJECT,'SOURCE_STREAM_BOUND')
        namespace,name=row['namespace'],row['type_name']
        if namespace=='clock':
            require(maximum is None and name in {'OriginalClock','SourceTestClock'},'SOURCE_CLOCK_SCHEMA')
            result[pin]=OriginalClockSchema(pin) if name=='OriginalClock' else SourceTestClockSchema(pin)
        else:
            require(namespace=='completion' and name in COMPLETION_TYPES or namespace=='protected' and name=='ProtectedRecordEnvelope','SOURCE_SCHEMA_ALLOWLIST')
            result[pin]=SchemaRoute(pin,namespace,name,limits=common.ValidationLimits(stream_bytes=maximum))
    return result


def validate_registry_chain(result, *, publishers, authority, now, maximum_entries,
                            expected_hash=None, expected_reference=None, expected_attestation=None):
    """Verify original V2 signatures and every prefix link; never trust a row."""
    closed(result,{'registry_chain'},'REGISTRY_RESPONSE')
    chain=result['registry_chain'];require(type(chain) is list and 0<len(chain)<=maximum_entries,'REGISTRY_CHAIN_BOUND')
    selection_hash=common.digest(pr.validate('PublisherRootSelection',publishers).raw)
    previous=common.ZERO_SHA256;seen=set();last_time=None
    for index,envelope in enumerate(chain,1):
        value=pr.validate('RegistrySignature',envelope).payload();row=value['registration']
        require(value['signer_sha256']==publishers['registry_signer_public_sha256'],'REGISTRY_SIGNER')
        authority.signature_check(signer_pin=value['signer_sha256'],message=pr.registration_signing_bytes(row),signature=_hex(value['signature_hex'],64))
        require(row['binding']==publishers['binding'] and row['publisher_selection_sha256']==selection_hash
                and row['registry_authority_id']==publishers['registry_authority_id'] and row['sequence']==index
                and row['previous_entry_sha256']==previous,'REGISTRY_ORIGINAL_CHAIN')
        at=common.utc(row['registered_at_utc'])
        require(common.utc(publishers['not_before_utc'])<=at<=common.utc(now['utc'])
                and at<common.utc(publishers['expires_at_utc']) and (last_time is None or last_time<=at),'REGISTRY_ORIGINAL_STAMP')
        ref=row['record_ref'];att=row['attestation_ref']
        require(ref['binding']==publishers['binding'] and att['binding']==publishers['binding']
                and ref['publisher_selection_sha256']==att['publisher_selection_sha256']==selection_hash
                and att['record_kind']=='RECORD_ATTESTATION' and att['purpose']=='record-attestation'
                and att['publisher_id']==ref['publisher_id'] and att['root_id']==ref['root_id'],'REGISTRY_ATTESTATION_BINDING')
        publishers_for_ref=[p for p in publishers['publishers'] if p['publisher_id']==ref['publisher_id']]
        require(len(publishers_for_ref)==1,'REGISTRY_RECORD_PUBLISHER')
        appointed=publishers_for_ref[0]
        require(common.utc(appointed['not_before_utc'])<=at<common.utc(appointed['expires_at_utc']),'REGISTRY_PUBLISHER_ORIGINAL_STAMP')
        grants=[g for g in appointed['grants'] if g['root_id']==ref['root_id'] and g['record_kind']==ref['record_kind']
                and g['purpose']==ref['purpose'] and g['permitted_use']=='SOURCE_COMPLETION']
        require(len(grants)==1,'REGISTRY_SOURCE_COMPLETION_ONLY')
        role=PUBLISHER_ROUTES.get(ref['record_kind'],{}).get(ref['purpose'])
        require(role=='EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER' or role==appointed['role'],'REGISTRY_RECORD_ROLE')
        identity=common.digest(pr.validate('ProtectedRecordRef',ref).raw)
        require(identity not in seen,'REGISTRY_DUPLICATE');seen.add(identity)
        previous=common.digest(pr.validate('ProtectedRegistration',row).raw);last_time=at
    require(expected_hash is None or previous==expected_hash,'REGISTRY_REQUESTED_HASH')
    require(expected_reference is None or same(row['record_ref'],expected_reference),'REGISTRY_REQUESTED_REFERENCE')
    require(expected_attestation is None or same(row['attestation_ref'],expected_attestation),'REGISTRY_REQUESTED_ATTESTATION')
    return _snapshot(row)


class SourceRegistryClient:
    def __init__(self, *, transport, authority, publishers):
        self.transport,self.authority=transport,authority;self.publishers=_snapshot(publishers)

    def _current(self,selection,now):
        require(same(selection,self.publishers),'REGISTRY_SELECTION_SUBSTITUTION')
        return self.authority.current(selection,now)

    def read_registration(self, registration_sha256, *, selection, now):
        result=self.signed_chain(registration_sha256,selection=selection,now=now)
        return _snapshot(result['registry_chain'][-1]['registration'])

    def signed_chain(self, registration_sha256, *, selection, now):
        now=self._current(selection,now);_pin(registration_sha256)
        result=self.transport.request('READ_REGISTRATION',{'registration_sha256':registration_sha256},publisher_selection_sha256=self.authority.pin)
        current=self._current(selection,now)
        validate_registry_chain(result,publishers=selection,authority=self.authority,now=current,
            maximum_entries=self.transport.endpoint['maximum_registry_entries'],expected_hash=registration_sha256)
        return _snapshot(result)

    def register_exact_record(self, raw, reference, publisher_envelope, *, selection, now):
        now=self._current(selection,now);reference=pr.validate('ProtectedRecordRef',reference).payload()
        require(type(raw) is bytes and common.digest(raw)==reference['sha256'] and len(raw)==reference['bytes'],'REGISTRY_REQUEST_BYTES')
        self.authority.check_grant(reference,selection,now,required_use='SOURCE_COMPLETION')
        self.authority.attest(reference,publisher_envelope,selection,now)
        envelope_raw=pr.validate('ProtectedRecordEnvelope',publisher_envelope).raw
        att={**reference,'sha256':common.digest(envelope_raw),'object_id':common.digest(envelope_raw),'bytes':len(envelope_raw),
             'record_kind':'RECORD_ATTESTATION','purpose':'record-attestation'}
        result=self.transport.request('REGISTER_EXACT_RECORD',{'record_hex':raw.hex(),'reference':reference,'publisher_envelope':publisher_envelope},publisher_selection_sha256=self.authority.pin)
        current=self._current(selection,now)
        return validate_registry_chain(result,publishers=selection,authority=self.authority,now=current,
            maximum_entries=self.transport.endpoint['maximum_registry_entries'],expected_reference=reference,expected_attestation=att)


class SourcePublisherClient:
    def __init__(self, *, transport, publisher_id, role, authority, publishers, resolver):
        self.transport,self.publisher_id,self.role=transport,publisher_id,role
        self.authority,self.publishers,self.resolver=authority,_snapshot(publishers),resolver

    def __call__(self, raw, *, record_kind, purpose, now):
        require(PUBLISH_ROUTES.get(record_kind)==(purpose,self.role),'SOURCE_PUBLICATION_ROUTE')
        now=self.authority.current(self.publishers,now)
        result=self.transport.request('PUBLISH',{'record_hex':raw.hex(),'record_kind':record_kind,'purpose':purpose},publisher_selection_sha256=self.authority.pin)
        closed(result,{'use','registry_chain'},'PUBLICATION_RESPONSE')
        use=pr.validate('ProtectedReferenceUse',result['use']).payload();ref=use['reference']
        require(use['required_use']=='SOURCE_COMPLETION' and ref['publisher_id']==self.publisher_id
                and ref['record_kind']==record_kind and ref['purpose']==purpose and ref['sha256']==common.digest(raw)
                and ref['bytes']==len(raw),'PUBLICATION_EXACT_RECORD')
        current=self.authority.current(self.publishers,now)
        validate_registry_chain({'registry_chain':result['registry_chain']},publishers=self.publishers,authority=self.authority,now=current,
            maximum_entries=self.transport.endpoint['maximum_registry_entries'],expected_hash=use['registration_sha256'],expected_reference=ref)
        require(self.resolver.resolve(use,selection=self.publishers,now=current)==raw,'PUBLICATION_ORIGINAL_READBACK')
        self.authority.current(self.publishers,current)
        return use


class SourceCompletionBindings:
    def __init__(self, *, config, public_keys, clock, original_deadline, base_execution_gate,
                 source_manifest_raw, completion_material_raw, completion_selection_raw, selection_use):
        closed(config,CONFIG_FIELDS,'SOURCE_BINDINGS_CONFIG');require(config['format']==CONFIG_FORMAT,'SOURCE_BINDINGS_FORMAT')
        self.config=_snapshot(config);self._clock=clock;self._base_gate=base_execution_gate
        require(callable(clock) and callable(base_execution_gate),'SOURCE_BOUND_CLOCK_AND_GATE')
        self.deadline=method.validate('Stamp',original_deadline).payload()
        self.publishers=pr.validate('PublisherRootSelection',config['publisher_selection']).payload()
        self.publisher_raw=pr.validate('PublisherRootSelection',self.publishers).raw
        self.publisher_pin=common.digest(self.publisher_raw)
        self.keys={_pin(k):bytes(v) for k,v in public_keys.items()}
        require(all(len(v)==32 and common.digest(v)==k for k,v in self.keys.items()),'PUBLIC_KEY_PINS')
        authorizer_pin=_pin(config['authorizer_public_sha256']);require(authorizer_pin in self.keys,'AUTHORIZER_PUBLIC_KEY')
        self.signature=_hex(config['selection_signature_hex'],64);self.verifier=Ed25519Verifier()
        self._current_client=LocalCompletionClient(endpoint=config['current_endpoint'],clock=self.raw_now,original_deadline=self.deadline)
        self.authority=SelectionProvider(selected_raw=self.publisher_raw,selected_sha256=self.publisher_pin,
            selection_signature=self.signature,authorizer_public_key=self.keys[authorizer_pin],authorizer_public_sha256=authorizer_pin,
            verifier=self.verifier,public_keys=self.keys,schema_routes=selected_schema_routes(config['schema_routes']),clock=self.raw_now,
            current_authority_guard=self.current_authority_guard,original_deadline=self.deadline,local_principal_id=config['local_principal_id'])
        self.registry=SourceRegistryClient(transport=LocalCompletionClient(endpoint=config['registry_endpoint'],clock=self.raw_now,original_deadline=self.deadline),
            authority=self.authority,publishers=self.publishers)
        self.files=ProtectedFiles(self.authority)
        self.resolver=ProtectedResolver(authority=self.authority,registry=self.registry,files=self.files)
        self.selection_raw=bytes(completion_selection_raw);self.selection=co.decode('CompletionSelection2',self.selection_raw).payload()
        self.selection_use=pr.validate('ProtectedReferenceUse',selection_use).payload()
        self.source_manifest_raw=bytes(source_manifest_raw);self.material_raw=bytes(completion_material_raw)
        require(common.digest(self.source_manifest_raw)==_pin(config['source_manifest_sha256'])==self.selection['binding']['source_manifest_sha256']
                and common.digest(self.material_raw)==_pin(config['completion_material_sha256']),'SOURCE_REVIEW_PINS')
        self.material=common.decode_json(self.material_raw,limit=common.MAX_GRAPH)
        require(self.material['source_manifest_sha256']==config['source_manifest_sha256'],'SOURCE_MATERIAL_BINDING')
        require(self.selection['observer_id']==config['observer_publisher_id'] and self.selection['verifier_id']==config['verifier_id']
                and self.selection['verifier_component_sha256']==_pin(config['verifier_component_sha256']),'SOURCE_VERIFIER_APPOINTMENT')
        for identifier,role in ((config['observer_publisher_id'],'COMPLETION_OBSERVER'),(config['custody_publisher_id'],'CUSTODY')):
            matches=[p for p in self.publishers['publishers'] if p['publisher_id']==identifier]
            require(len(matches)==1 and matches[0]['role']==role,'SOURCE_PUBLISHER_APPOINTMENT')
        self.observer_publish=SourcePublisherClient(transport=LocalCompletionClient(endpoint=config['observer_endpoint'],clock=self.raw_now,original_deadline=self.deadline),
            publisher_id=config['observer_publisher_id'],role='COMPLETION_OBSERVER',authority=self.authority,publishers=self.publishers,resolver=self.resolver)
        self.custody_publish=SourcePublisherClient(transport=LocalCompletionClient(endpoint=config['custody_endpoint'],clock=self.raw_now,original_deadline=self.deadline),
            publisher_id=config['custody_publisher_id'],role='CUSTODY',authority=self.authority,publishers=self.publishers,resolver=self.resolver)
        self.parsers={}
        require(type(config['parser_routes']) is list and 0<len(config['parser_routes'])<=16,'SOURCE_PARSER_ROUTES')
        for row in config['parser_routes']:
            closed(row,{'component_sha256','entrypoint'},'SOURCE_PARSER_ROUTE');_pin(row['component_sha256'])
            require(row['entrypoint'] in PARSER_ENTRYPOINTS,'SOURCE_PARSER_ENTRYPOINT')
            key=(row['component_sha256'],row['entrypoint']);require(key not in self.parsers,'SOURCE_PARSER_DUPLICATE')
            self.parsers[key]=FrameworkParser(component_sha256=key[0],entrypoint=key[1])
        self._check_selected_source()

    def raw_now(self):
        now=method.validate('Stamp',self._clock()).payload()
        require(common.utc(now['utc'])<common.utc(self.deadline['utc']) and now['boottime_ns']<self.deadline['boottime_ns'],'ORIGINAL_SOURCE_DEADLINE')
        return now

    def current_authority_guard(self, now):
        # No call to execution_gate(), SelectionProvider.current(), or a clock
        # wrapped by this guard: the transport uses only the raw bounded reader.
        supplied=method.validate('Stamp',now).payload();current=self.raw_now()
        require(common.utc(supplied['utc'])<=common.utc(current['utc']) and supplied['boottime_ns']<=current['boottime_ns'],'SOURCE_FUTURE_STAMP')
        call_none(self._base_gate)
        answer=self._current_client.request('CURRENT_SELECTION',{},publisher_selection_sha256=self.publisher_pin)
        closed(answer,{'selection','signature_hex'},'CURRENT_SELECTION_RESPONSE')
        raw=pr.validate('PublisherRootSelection',answer['selection']).raw
        require(raw==self.publisher_raw,'CURRENT_SELECTION_CHANGED')
        signature=_hex(answer['signature_hex'],64)
        call_none(self.verifier.verify,public_key=self.keys[self.config['authorizer_public_sha256']],
                  message=pr.selection_signing_bytes(answer['selection']),signature=signature)
        after=self.raw_now()
        require(common.utc(self.publishers['not_before_utc'])<=common.utc(current['utc'])<=common.utc(after['utc'])
                <common.utc(self.publishers['expires_at_utc']) and current['boottime_ns']<=after['boottime_ns'],'CURRENT_SELECTION_EXPIRED')
        call_none(self._base_gate)

    def execution_gate(self):self.current_authority_guard(self.raw_now())

    def _use(self,use,kind,purpose,raw=None):
        value=pr.validate('ProtectedReferenceUse',use).payload();ref=value['reference']
        require(value['required_use']=='SOURCE_COMPLETION' and ref['record_kind']==kind and ref['purpose']==purpose
                and ref['binding']==self.selection['binding']==self.publishers['binding']
                and ref['publisher_selection_sha256']==self.publisher_pin,'SOURCE_SELECTED_REFERENCE')
        if raw is not None:require(ref['sha256']==common.digest(raw) and ref['bytes']==len(raw),'SOURCE_EXPECTED_CONTENT')

    def _check_selected_source(self):
        selected=self.selection;material=self.material
        require(selected['publisher_selection_sha256']==self.publisher_pin and tuple(material['group_order'])==co.GROUP_ORDER
                and tuple(g['group_id'] for g in selected['groups'])==co.GROUP_ORDER,'SOURCE_GROUP_ORDER')
        self._use(self.selection_use,'COMPLETION_SELECTION','completion-selection',self.selection_raw)
        inventory={'format':'forex.completion-source-inventory/1','binding':selected['binding'],
            'source_manifest_sha256':self.config['source_manifest_sha256'],'test_files':material['test_files'],
            'group_order':material['group_order'],'test_roots':material['test_roots']}
        manifest=common.decode_json(self.source_manifest_raw,limit=common.MAX_GRAPH)
        require(type(manifest.get('files')) is list,'SOURCE_MANIFEST_FILES')
        files={row['path']:row['sha256'] for row in manifest['files']}
        require(len(files)==len(manifest['files']),'SOURCE_MANIFEST_DUPLICATE')
        expected_files={}
        for path,digest in files.items():
            roots=[r for r in material['test_roots'] if path.startswith(r['source_relative_directory']+'/')
                   and any(path.endswith(s) for s in r['suffixes'])]
            require(len(roots)<=1,'SOURCE_TEST_ROOT_OVERLAP')
            if roots:expected_files[path]=(digest,roots[0]['group_id'])
        observed_files={r['source_relative_path']:(r['source_file_sha256'],r['group_id']) for r in material['test_files']}
        require(len(observed_files)==len(material['test_files']) and observed_files==expected_files,'SOURCE_COMPLETE_TEST_FILES')
        self._use(selected['source_inventory_ref'],'SOURCE_INVENTORY','completion-source-inventory',co.validate('SourceInventory',inventory).raw)
        for group in selected['groups']:
            gid=group['group_id'];entries=material['collection_entries'][gid];ids=sorted(row['test_id'] for row in entries)
            require(len(ids)==len(set(ids))==group['expected_test_count'],'SOURCE_EXPECTED_DENOMINATOR')
            require(all(expected_files.get(row['source_relative_path'])==(row['source_file_sha256'],gid) for row in entries),'SOURCE_INVENTORY_FILE')
            require(group['mode']==('NODE_VERSION' if gid=='node-version' else 'NODE_TAP' if gid=='ui' else 'PYTHON_METHODS'),'SOURCE_GROUP_MODE')
            expected={'format':'forex.test-collection-inventory/1','binding':selected['binding'],'group_id':gid,
                'source_manifest_sha256':self.config['source_manifest_sha256'],'entries':entries,'expected_count':len(ids),
                'test_ids_sha256':common.digest(common.canonical_bytes(ids))}
            self._use(group['expected_inventory'],'COLLECTION_INVENTORY','test-collection-inventory',co.validate('CollectionInventory',expected).raw)
            self._use(group['command'],'COMMAND_PIN','test-command-pin');self._use(group['parser'],'PARSER_PIN','test-parser-pin')

    def authenticate_selection(self, selection, *, now):
        require(co.validate('CompletionSelection2',selection).raw==self.selection_raw,'SOURCE_SELECTION_SUBSTITUTION')
        current=self.authority.current(self.publishers,now)
        require(common.utc(selection['not_before_utc'])<=common.utc(current['utc'])<common.utc(selection['expires_at_utc']),'SOURCE_SELECTION_EXPIRED')
        require(self.resolver.resolve(self.selection_use,selection=self.publishers,now=current)==self.selection_raw,'SOURCE_SELECTION_ORIGINAL_READBACK')
        self._check_selected_source()

    def verify_completion(self, report_use, observation_use, *, now):
        self.authenticate_selection(self.selection,now=now)
        report=self.resolver.resolve(report_use,selection=self.publishers,now=self.raw_now())
        observation=self.resolver.resolve(observation_use,selection=self.publishers,now=self.raw_now())
        verifier=CompletionVerifier(selection_use=self.selection_use,report_use=report_use,observation_use=observation_use,
            verifier_id=self.config['verifier_id'],verifier_component_sha256=self.config['verifier_component_sha256'],
            source_manifest_raw=self.source_manifest_raw,parser_implementations=self.parsers,registry=self.registry,
            clock=self.raw_now,current_authority_guard=self.current_authority_guard,original_deadline=self.deadline)
        receipt=verifier.verify(self.selection,co.decode('SourceTestReport2',report).payload(),co.decode('CompletionObservation2',observation).payload(),
            resolver=self.resolver,publishers=self.publishers,now=self.raw_now())
        return co.validate('CompletionReceipt2',receipt).raw

    def publish_completion(self, report_use, observation_use, *, now):
        raw=self.verify_completion(report_use,observation_use,now=now)
        use=self.observer_publish(raw,record_kind='SOURCE_TEST_COMPLETION',purpose='source-test-completion',now=self.raw_now())
        require(self.resolver.resolve(use,selection=self.publishers,now=self.raw_now())==raw,'FINAL_COMPLETION_READBACK')
        return use,raw


def bind_source_completion(*, config, public_keys, clock, original_deadline, base_execution_gate,
                           source_manifest_raw, completion_material_raw, completion_selection_raw, selection_use):
    return SourceCompletionBindings(config=config,public_keys=public_keys,clock=clock,original_deadline=original_deadline,
        base_execution_gate=base_execution_gate,source_manifest_raw=source_manifest_raw,completion_material_raw=completion_material_raw,
        completion_selection_raw=completion_selection_raw,selection_use=selection_use)
