"""Fixed source-only deployment primitives; import performs no I/O."""
import os
from pathlib import Path
import select
import socket
import stat
import sys
import time
import launch_common as c

ROLES = ('current', 'registry', 'observer', 'custody')
IPC = '/var/lib/cas-fx-8e1a63c5-ipc'
GROUP = 'cas-fx-8e1a63c5-read'
IMPORT_ROOTS = ('src', 'shared-interface', 'operational/authority/source',
                'operational/measurement/source', 'operational/custody/source')
ROLE_FIELDS = {'format','role','controller','prepared_sha256','source_selection',
    'test_deadline_utc','clock_domain','clock_anchor_stamp','current_register',
    'client_config','public_keys','peers','publish_routes','completion_selection',
    'selection_use','original_clock','source_manifest','completion_material',
    'signer_public_sha256'}
CONTROLLER_FIELDS = {'format','status','run_id','execution_mode','model_launch_allowed',
    'model_inference_calls_limit','stage_b_status','worker_count','shared_first30days_ceiling_usd',
    'controller_parent','test_runtime_mode','owner_receipt','coordinator_receipt','budget_receipt',
    'topology_acceptance','source_selection','runtime_inventory','python_wheel_lock','stop_proof',
    'egress_receipt','bootstrap_record','t0_utc','work_deadline_utc','reader_group_name',
    'reader_group_gid','reader_group_create','infrastructure_files','original_clock',
    'appointment_authority','delivery_channels'}

def closed(value, fields, code):
    c.need(type(value) is dict and set(value) == set(fields), code)
    return value

def load_source(selection):
    """Verify every frozen member before fixed imports; no arbitrary module route."""
    raw, _ = c.pinned(selection['source_manifest'])
    manifest = c.decode(raw,False)
    root = c.BASE+'/source'
    c.need(selection['entrypoint']['path']==root+'/source_test_bootstrap.py','Fixed source entrypoint')
    c.under_base(root)
    c.need(root != c.BASE and type(manifest['files']) is list, 'Source root')
    seen=set()
    for row in manifest['files']:
        name=row['path']
        c.need(type(name) is str and name not in seen and not name.startswith('/')
               and '\\' not in name and all(x not in ('','.','..') for x in name.split('/')),
               'Source member')
        seen.add(name)
        c.pinned({'path':root+'/'+name,'bytes':row['bytes'],'sha256':row['sha256']},
                 maximum=16*1024*1024)
    c.need({'source_test_bootstrap.py','source_test_namespace_observer.py'} <= seen,
           'Namespace successor files missing')
    for leaf in reversed(IMPORT_ROOTS):
        sys.path.insert(0,root+'/'+leaf)
    sys.path.insert(0,root)
    return raw

def reviewed_runtime(selection, infrastructure_files):
    """An exact independent review is required; candidate04 alone cannot satisfy it."""
    c.need(selection['status']=='INDEPENDENTLY_SOURCE_REVIEWED','Source review hold')
    raw,_=c.pinned(selection['review_receipt'])
    review=c.decode(raw)
    closed(review,{'format','decision','source_manifest_sha256','completion_material_sha256',
        'infrastructure_files','review_report'},'Independent runtime review')
    c.need(review['format']=='forex.source-test-runtime-review/1'
           and review['decision']=='ACCEPTED_SOURCE'
           and review['source_manifest_sha256']==selection['source_manifest']['sha256']
           and review['completion_material_sha256']==selection['completion_material']['sha256']
           and review['infrastructure_files']==infrastructure_files,'Runtime review hold')
    c.pinned(review['review_report'])
    rows={row['path']:row for row in infrastructure_files}
    c.need(len(rows)==len(infrastructure_files),'Duplicate infrastructure pin')
    directory=str(Path(__file__).resolve().parent)
    required={directory+'/'+name for name in ('launch_common.py','source_runtime_common.py',
        'source_role_service.py','source_test_controller.py','source_test_launcher.py','source_test_worker.py')}
    c.need(required<=set(rows),'Incomplete infrastructure freeze')
    for row in infrastructure_files:c.pinned(row)

def read_frame(fd, deadline, maximum=4*1024*1024):
    def exact(size):
        out=bytearray()
        while len(out)<size:
            ready,_,_=select.select([fd],[],[],min(.2,deadline.remaining()))
            if ready:
                value=os.read(fd,size-len(out))
                c.need(value,'Control pipe closed')
                out.extend(value)
        return bytes(out)
    size=int.from_bytes(exact(4),'big')
    c.need(0<size<=maximum,'Control frame bound')
    return c.decode(exact(size))

def write_frame(fd, value, deadline, maximum=4*1024*1024):
    raw=c.canonical(value)
    c.need(0<len(raw)<=maximum,'Control frame bound')
    view=memoryview(len(raw).to_bytes(4,'big')+raw)
    while view:
        _,ready,_=select.select([],[fd],[],min(.2,deadline.remaining()))
        if ready:
            n=os.write(fd,view[:4096]);c.need(n>0,'Control write failed');view=view[n:]

def relay_signer_frame(source_fd, target_fd, deadline):
    """Only the non-secret length enters controller memory; splice opaque bytes."""
    c.need(sys.platform=='linux' and hasattr(os,'splice'),'Linux opaque pipe delivery')
    header=bytearray()
    while len(header)<4:
        ready,_,_=select.select([source_fd],[],[],min(.2,deadline.remaining()))
        if ready:
            part=os.read(source_fd,4-len(header));c.need(part,'Signer header EOF');header.extend(part)
    remaining=int.from_bytes(header,'big')
    c.need(0<remaining<=4096,'Signer frame bound')
    view=memoryview(header)
    while view:
        _,ready,_=select.select([],[target_fd],[],min(.2,deadline.remaining()))
        if ready:
            count=os.write(target_fd,view);c.need(count>0,'Signer header delivery');view=view[count:]
    os.set_blocking(source_fd,False);os.set_blocking(target_fd,False)
    try:
        while remaining:
            deadline.remaining()
            try:
                count=os.splice(source_fd,target_fd,remaining,flags=os.SPLICE_F_NONBLOCK)
                c.need(count>0,'Signer delivery truncated');remaining-=count
            except BlockingIOError:
                select.select([source_fd],[target_fd],[],min(.01,deadline.remaining()))
    finally:
        os.close(source_fd)
        os.set_blocking(target_fd,True)

def public_identity(pid=None):
    pid=os.getpid() if pid is None else pid
    process=c.process_identity(pid)
    return {**process,'gid':os.stat('/proc/'+str(pid)).st_gid,
            'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}

def directory_identity(path):
    value=os.stat(path,follow_symlinks=False)
    c.need(stat.S_ISDIR(value.st_mode),'Directory required')
    return dict(path=path,device=value.st_dev,inode=value.st_ino,uid=value.st_uid,
                gid=value.st_gid,mode=stat.S_IMODE(value.st_mode))

def endpoint(path, who, *, maximum=4*1024*1024, timeout=30000):
    st=os.stat(path,follow_symlinks=False)
    c.need(stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode)==0o660,'Socket mode')
    return dict(path=path,device=st.st_dev,inode=st.st_ino,uid=st.st_uid,gid=st.st_gid,
        mode=stat.S_IMODE(st.st_mode),peer_pid=who['pid'],peer_uid=who['uid'],
        peer_gid=who['gid'],peer_start_ticks=who['start_ticks'],boot_id=who['boot_id'],
        maximum_frame_bytes=maximum,timeout_ms=timeout,maximum_registry_entries=4096)

def pair_reader(deadline):
    def read():
        deadline.remaining()
        domain,stamp=c.observe_pair()
        c.need(domain==deadline.domain,'Clock domain changed')
        return stamp
    return read

def paired_deadline(deadline):
    return {'utc':deadline.end.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            'boottime_ns':deadline.end_ns}

def role_guard(config, config_raw, config_pin, deadline):
    """Root-selected live controller plus fixed config, never an approval boolean."""
    c.need(c.process_identity(config['controller']['pid'])==config['controller']
           and config['controller']['uid']==0,'Controller unavailable')
    actual,_=c.pinned(config_pin)
    c.need(actual==config_raw,'Role configuration replaced')
    deadline.remaining()

def bind_principal(config, prepared, public_keys):
    """The role cannot use a publisher ID or signer outside its exact appointment."""
    from cas_forex_operational_contracts import protected as pr
    selection=pr.validate('PublisherRootSelection',config['client_config']['publisher_selection']).payload()
    role=config['role'];identifier=config['client_config']['local_principal_id']
    root=next((r for r in selection['roots'] if
        r['absolute_directory']==prepared['published_root']['path']),None)
    actual=prepared['published_root']
    c.need(root is not None and root['writer_principal_ids']==[identifier]
        and tuple(root['expected_'+k] for k in ('device','inode','uid','gid','mode'))==
            tuple(actual[k] for k in ('device','inode','uid','gid','mode')),'Actual role root/identity')
    if role=='registry':
        c.need(identifier==selection['registry_authority_id']
            and root['root_id']==selection['registry_root_id']
            and config['signer_public_sha256']==selection['registry_signer_public_sha256'],
            'Actual registry appointment')
    elif role in ('observer','custody'):
        rows=[r for r in selection['publishers'] if r['publisher_id']==identifier]
        c.need(len(rows)==1 and rows[0]['role']=={'observer':'COMPLETION_OBSERVER','custody':'CUSTODY'}[role]
               and rows[0]['signer_public_sha256']==config['signer_public_sha256'],'Actual publisher appointment')
        c.need(all(r['root_id']==root['root_id'] for r in config['publish_routes']),'Publisher root route')
    if role!='current':
        c.need(config['signer_public_sha256'] in public_keys,'Selected signer key absent')

def signer_from_frame(frame, expected_pin, public_keys, domain):
    from cas_forex_authority.authentication import Ed25519Signer
    closed(frame,{'format','public_sha256','private_hex'},'Signer delivery shape')
    c.need(frame['format']=='forex.selected-existing-signer-delivery/1'
           and frame['public_sha256']==expected_pin,'Selected signer differs')
    public=public_keys[expected_pin]
    c.need(type(frame['private_hex']) is str and len(frame['private_hex'])==64,
           'Selected signer byte count')
    secret=bytearray.fromhex(frame['private_hex'])
    frame.clear()
    c.need(len(secret)==32 and c.digest(public)==expected_pin,'Signer pin')
    from importlib.metadata import version
    c.need(version('cryptography')=='50.0.2','Pinned signing runtime')
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    try:
        c.need(Ed25519PrivateKey.from_private_bytes(bytes(secret)).public_key().public_bytes_raw()==public,
               'Existing signer does not match appointment')
    except BaseException:
        secret[:]=b'\0'*len(secret)
        raise
    # No secret serialization, file, argv, environment, stdout or error reporting.
    signer=Ed25519Signer(load_selected_private_bytes=lambda: bytes(secret),
                        public_key=public,allowed_domains=frozenset({domain}))
    return signer,secret

def fixed_keys(values):
    c.need(type(values) is dict and 0<len(values)<=128,'Public keys')
    result={}
    for pin,value in values.items():
        c.need(c.HASH.fullmatch(pin) and type(value) is str and len(value)==64,'Public key')
        raw=bytes.fromhex(value);c.need(len(raw)==32 and c.digest(raw)==pin,'Public key pin')
        result[pin]=raw
    return result

def input_channel(fd, selected):
    import fcntl
    closed(selected,{'fd','device','inode','uid','gid','mode'},'Selected delivery pipe')
    st=os.fstat(fd)
    c.need(selected['fd']==fd and all(type(selected[k]) is int for k in selected)
        and (st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==
            tuple(selected[k] for k in ('device','inode','uid','gid','mode'))
        and stat.S_ISFIFO(st.st_mode) and st.st_uid==0
        and fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY,
        'Exact root-selected inherited read pipe')

def make_ports(config, config_raw, config_pin, deadline, signer):
    """Concrete fixed constructors shared by role and setup controller."""
    from cas_forex_operational_contracts import protected as pr, common
    from cas_forex_authority.authentication import Ed25519Verifier
    from custody_runtime.selection_provider import SelectionProvider
    from custody_runtime.protected_registry import ProtectedFiles, ProtectedRegistry, ProtectedResolver
    from custody_runtime.source_completion import selected_schema_routes, SourceRegistryClient
    from custody_runtime.completion_transport import LocalCompletionClient
    from custody_runtime.completion_hosts import CurrentSelectionFile
    client=config['client_config'];keys=fixed_keys(config['public_keys'])
    selection=pr.validate('PublisherRootSelection',client['publisher_selection']).payload()
    raw=pr.validate('PublisherRootSelection',selection).raw
    pin=common.digest(raw);clock=pair_reader(deadline);end=paired_deadline(deadline)
    base=lambda:role_guard(config,config_raw,config_pin,deadline)
    def guard(now):
        base()
        if config['role']=='current':
            body=current_handler({'operation':'CURRENT_SELECTION','payload':{},
                                  'publisher_selection_sha256':pin})
        else:
            body=current_client.request('CURRENT_SELECTION',{},publisher_selection_sha256=pin)
        c.need(body=={'selection':selection,'signature_hex':client['selection_signature_hex']},
               'Current selection withdrawn or changed')
    register=config['current_register']
    current_handler=CurrentSelectionFile(**register,
        authorizer_public_key=keys[client['authorizer_public_sha256']],
        authorizer_public_sha256=client['authorizer_public_sha256'],
        verifier=Ed25519Verifier(),clock=clock,original_deadline=end) if config['role']=='current' else None
    current_client=LocalCompletionClient(endpoint=client['current_endpoint'],clock=clock,
        original_deadline=end) if config['role']!='current' else None
    authority=SelectionProvider(selected_raw=raw,selected_sha256=pin,
        selection_signature=bytes.fromhex(client['selection_signature_hex']),
        authorizer_public_key=keys[client['authorizer_public_sha256']],
        authorizer_public_sha256=client['authorizer_public_sha256'],verifier=Ed25519Verifier(),
        public_keys=keys,schema_routes=selected_schema_routes(client['schema_routes']),
        clock=clock,current_authority_guard=guard,original_deadline=end,
        local_principal_id=client['local_principal_id'],
        registry_signer=signer if config['role']=='registry' else None)
    files=ProtectedFiles(authority)
    registry=ProtectedRegistry(authority=authority,files=files) if config['role']=='registry' else SourceRegistryClient(
        transport=LocalCompletionClient(endpoint=client['registry_endpoint'],clock=clock,
            original_deadline=end),authority=authority,publishers=selection)
    resolver=ProtectedResolver(authority=authority,registry=registry,files=files)
    return authority,files,registry,resolver,selection,clock,base,current_handler

def peer_policy(endpoint_record, identity, operations):
    return {'selection':{**endpoint_record,'peer_pid':identity['pid'],'peer_uid':identity['uid'],
            'peer_gid':identity['gid'],'peer_start_ticks':identity['start_ticks'],
            'boot_id':identity['boot_id']},'operations':sorted(operations)}

def authenticate_peer(connection, peers):
    from custody_runtime.completion_transport import peer_identity
    import struct
    pid,uid,gid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    matches=[x for x in peers if (x['selection']['peer_pid'],x['selection']['peer_uid'],
                                 x['selection']['peer_gid'])==(pid,uid,gid)]
    c.need(len(matches)==1,'Unselected client')
    peer_identity(connection,matches[0]['selection'])
    return matches[0]

