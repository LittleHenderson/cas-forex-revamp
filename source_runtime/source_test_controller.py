"""One-shot root source-test composition. No execution on import.

Inputs are preaccepted root-protected deployment/configuration receipts, actual
external selection signatures and existing signer deliveries. This controller
does not grant approval, appoint itself, sign reviewer records, or reset clocks.
"""
import argparse
import grp
import logging
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import time

_logger = logging.getLogger(__name__)

def unit_name(role):
    return 'cas-fx-8e1a63c5-'+role

class LiveDeadline:
    """Every wait also observes the original native selection and live owners."""
    def __init__(self,base,parent,owned,path,raw,c):
        self.base,self.parent,self.owned,self.path,self.raw,self.c=base,parent,owned,path,raw,c
    def __getattr__(self,name):return getattr(self.base,name)
    def remaining(self,reserve=0):
        c=self.c
        c.need(c.process_identity(self.parent['pid'])==self.parent,'Outer controller unavailable')
        c.need(c.read_protected(self.path)[0]==self.raw,'Native selection withdrawn or changed')
        for unit,description,process,error in self.owned:
            if unit!=c.UNIT:c.need(process.poll() is None,'Prepared role process exited')
        return self.base.remaining(reserve)

def artifact(path,value,c):
    raw,_=c.create_retained(path,value)
    return {'path':path,'bytes':len(raw),'sha256':c.digest(raw)}

def admitted(config,raw,path,pin,c):
    """Verify the exact root-controlled native admission passed by the caller."""
    c.need(os.getuid()==os.geteuid()==0 and sys.platform=='linux'
           and sys.version_info[:2]==(3,12),'Root selected Linux Python3.12')
    c.need(c.digest(raw)==pin and config['format']=='forex.source-test-controller-selection/1',
           'Controller selection pin')
    c.guards(config)
    c.need(config['status']=='DIRECT_OWNER_AND_COORDINATOR_ACCEPTED'
           and type(config['worker_count']) is int and config['worker_count']==1
           and config['shared_first30days_ceiling_usd']=='15.00',
           'Independent native acceptance required')
    for name in ('owner_receipt','coordinator_receipt','budget_receipt','topology_acceptance',
                 'source_selection','runtime_inventory','python_wheel_lock',
                 'stop_proof','egress_receipt','bootstrap_record'):
        c.pinned(config[name])
    c.need(config['controller_parent']==c.process_identity(os.getppid())
           and config['controller_parent']['uid']==0,'Selected outer controller unavailable')
    c.need(config['test_runtime_mode']=='SOURCE_ONLY_NO_MODEL','Source execution scope')
    c.need(config['run_id']==c.RUN,'Exact run identity')
    return c.process_identity(os.getpid())

def ensure_unit_unused(unit,deadline,c):
    value=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=LoadState','--value'],
        check=True,capture_output=True,text=True,timeout=min(3,deadline.remaining(5))).stdout.strip()
    c.need(value=='not-found','Existing unit cannot be adopted')

def make_dir(path,uid,gid,mode,c):
    """Exclusive setup only after native admission; preserves all old paths."""
    c.absolute(path)
    c.need(not os.path.lexists(path),'Existing setup path cannot be reused')
    os.mkdir(path,mode)
    os.chown(path,uid,gid,follow_symlinks=False)
    os.chmod(path,mode,follow_symlinks=False)

def prepare_existing_dir(path,uid,gid,mode,c):
    """Apply owner and SGID directory mode only after verifying an existing real directory."""
    c.absolute(path)
    st=os.lstat(path)
    c.need(stat.S_ISDIR(st.st_mode),'Role path must be directory')
    os.chown(path,uid,gid,follow_symlinks=False)
    os.chmod(path,mode,follow_symlinks=False)

def prepare_role_directories(role,who,gid,c,s):
    """Root-only preparation; the restricted child performs no SGID mutations."""
    c.need(os.geteuid()==0,'Root directory preparer required')
    c.need(role in s.ROLES,'Selected role')
    for leaf in (role,role+'-records'):
        prepare_existing_dir(s.IPC+'/'+leaf,who['uid'],gid,0o2750,c)
    make_dir(s.IPC+'/'+role+'-records/objects',who['uid'],gid,0o2750,c)
    return {'format':'forex.source-role-prepare/1',
        'socket_parent':s.directory_identity(s.IPC+'/'+role),
        'published_root':s.directory_identity(s.IPC+'/'+role+'-records')}

def ensure_reader_group(config,runtime,deadline,c,s):
    c.need(config['reader_group_name']==s.GROUP and type(config['reader_group_gid']) is int
           and config['reader_group_gid']>0 and type(config['reader_group_create']) is bool,
           'Exact selected reader group')
    try:existing=grp.getgrnam(s.GROUP)
    except KeyError:existing=None
    if existing is not None:
        c.need(not config['reader_group_create'] and existing.gr_gid==config['reader_group_gid']
               and not existing.gr_mem,'Existing reader group differs or has host members')
        return
    c.need(config['reader_group_create'],'Reader group absent')
    try:grp.getgrgid(config['reader_group_gid'])
    except KeyError:pass
    else:raise RuntimeError('Selected GID is occupied')
    rows=[r for r in runtime['files'] if r['path']=='/usr/sbin/groupadd']
    c.need(len(rows)==1,'Native group setup executable must be pinned')
    c.pinned(rows[0])
    subprocess.run(['/usr/sbin/groupadd','--system','--gid',str(config['reader_group_gid']),s.GROUP],
        check=True,capture_output=True,timeout=min(5,deadline.remaining(10)),
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
    actual=grp.getgrnam(s.GROUP)
    c.need(actual.gr_gid==config['reader_group_gid'] and not actual.gr_mem,'Created group readback')

_SOURCE_RUNTIME_DIR = str(Path(__file__).resolve().parent)
if _SOURCE_RUNTIME_DIR not in sys.path:
    sys.path.insert(0, _SOURCE_RUNTIME_DIR)
from systemd_ceilings import SOURCE_UNIT_CEILINGS  # noqa: E402

def role_command(role,startup,seconds,runtime_directory,c):
    unit=unit_name(role)
    properties={'Description':'forex-source-role-'+startup['sha256'],'Type':'exec','Restart':'no',
        'RuntimeMaxSec':str(seconds),'TimeoutStopSec':'1','KillMode':'control-group',
        'SendSIGKILL':'yes','DynamicUser':'yes','NoNewPrivileges':'yes','UMask':'0027',
        'CapabilityBoundingSet':'','AmbientCapabilities':'','PrivateNetwork':'yes',
        'PrivateDevices':'yes','PrivateTmp':'yes','ProtectSystem':'strict','ProtectHome':'yes',
        'ProtectProc':'default','ProcSubset':'all','ProtectKernelTunables':'yes',
        'ProtectKernelModules':'yes','ProtectKernelLogs':'yes','ProtectControlGroups':'yes',
        'RestrictSUIDSGID':'yes','RestrictNamespaces':'yes','LockPersonality':'yes',
        'RestrictAddressFamilies':'AF_UNIX','InaccessiblePaths':'-/root -/home -/media -/mnt',
        'ReadOnlyPaths':c.BASE,'StateDirectory':unit,'StateDirectoryMode':'0700',
        'BindReadOnlyPaths':c.BASE+'/runtime/python-site:/usr/local/lib/python3.12/dist-packages',
        # Paths are created after DynamicUser has an actual UID. The narrow
        # exact writable mounts therefore cannot be created before the role.
        # The root IPC tree remains read-only; only these two children get RW.
        'ReadWritePaths':'-/var/lib/cas-fx-8e1a63c5-ipc/'+role+' -/var/lib/cas-fx-8e1a63c5-ipc/'+role+'-records',
        'SupplementaryGroups':'cas-fx-8e1a63c5-read','Environment':'HOME=/tmp',
        **SOURCE_UNIT_CEILINGS}
    return ['/usr/bin/systemd-run','--unit='+unit,'--wait','--pipe','--quiet']+[
        '--property='+k+'='+v for k,v in properties.items()]+[
        '/usr/bin/python3','-I','-B',runtime_directory+'/source_role_service.py',
        '--role',role,'--startup',startup['path'],'--startup-sha256',startup['sha256']]

def kill_owned(unit,description,c):
    """No broad process search/kill; stop only this exact new unit description."""
    try:
        actual=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=Description','--value'],
            capture_output=True,text=True,timeout=3).stdout.strip()
        if actual!=description:return False
        result=subprocess.run(['/usr/bin/systemctl','kill','--kill-whom=all','--signal=SIGKILL',unit],
            capture_output=True,timeout=3)
        return result.returncode==0
    except Exception:return False

def peer_rows(role,endpoints,identities,s):
    operations={'current':{'CURRENT_SELECTION'},
                'registry':{'READ_REGISTRATION','REGISTER_EXACT_RECORD'},
                'observer':{'PUBLISH'},'custody':{'PUBLISH'}}
    clients={'current':('controller','workload','registry','observer','custody'),
             'registry':('controller','workload','observer','custody'),
             'observer':('workload',),'custody':('workload',)}[role]
    rows=[]
    for client in clients:
        allowed=operations[role]
        if role=='registry' and client=='workload':allowed={'READ_REGISTRATION'}
        rows.append(s.peer_policy(endpoints[role],identities[client],allowed))
    return rows

def verify_appointment(value,observed,selection,accepted,c,s):
    from cas_forex_operational_contracts import protected as pr
    from cas_forex_authority.authentication import Ed25519Verifier
    s.closed(value,{'format','observations_sha256','client_config','public_keys',
        'principal_ids','root_ids','current_register','publish_routes','seed_records',
        'signer_public_sha256'},'Appointment fields')
    c.need(value['format']=='forex.source-test-observed-appointment/1'
           and value['observations_sha256']==c.digest(c.canonical(observed)),'Actual appointment binding')
    client=value['client_config'];publishers=pr.validate('PublisherRootSelection',client['publisher_selection']).payload()
    from custody_runtime.source_completion import CONFIG_FIELDS
    s.closed(client,CONFIG_FIELDS,'Closed client configuration')
    s.closed(accepted,{'public_keys','authorizer_public_sha256','signer_public_sha256',
        'principal_ids','evaluation_binding','client_policy','current_register'},'Native appointment authority')
    c.need(value['public_keys']==accepted['public_keys']
           and value['signer_public_sha256']==accepted['signer_public_sha256']
           and value['principal_ids']==accepted['principal_ids']
           and value['current_register']==accepted['current_register']
           and client['authorizer_public_sha256']==accepted['authorizer_public_sha256']
           and publishers['binding']==accepted['evaluation_binding'],
           'Appointment cannot introduce its own authority')
    c.need(publishers['binding']['run_id']==c.RUN,'Exact source-test run binding')
    s.closed(accepted['current_register'],{'path','device','inode','uid','gid','mode','maximum_bytes'},
             'Native authoritative current register')
    policy_fields={'authorizer_public_sha256','source_manifest_sha256','completion_material_sha256',
        'verifier_id','verifier_component_sha256','observer_publisher_id','custody_publisher_id',
        'schema_routes','parser_routes'}
    s.closed(accepted['client_policy'],policy_fields,'Pinned client policy')
    c.need({k:client[k] for k in policy_fields}==accepted['client_policy'],'Selected implementation pins')
    keys=s.fixed_keys(value['public_keys']);key=keys[client['authorizer_public_sha256']]
    Ed25519Verifier().verify(public_key=key,message=pr.selection_signing_bytes(publishers),
                            signature=bytes.fromhex(client['selection_signature_hex']))
    c.need(publishers['binding']['source_manifest_sha256']==selection['source_manifest']['sha256']
           and client['source_manifest_sha256']==selection['source_manifest']['sha256']
           and client['completion_material_sha256']==selection['completion_material']['sha256'],
           'Appointment source binding')
    c.need(set(value['principal_ids'])=={'controller','workload','current','registry','observer','custody'}
           and len(set(value['principal_ids'].values()))==6,'Distinct exact local principals')
    c.need(set(value['signer_public_sha256'])=={'registry','observer','custody'},'Only three existing signers')
    c.need(set(value['root_ids'])=={'controller','current','registry','observer','custody'},'Root set')
    c.need(len(publishers['roots'])==5,'No additional root capability')
    for role,root_id in value['root_ids'].items():
        root=next(r for r in publishers['roots'] if r['root_id']==root_id)
        actual=observed['external_root'] if role=='controller' else observed['roles'][role]['published_root']
        c.need(root['absolute_directory']==actual['path']
            and tuple(root['expected_'+k] for k in ('device','inode','uid','gid','mode'))==
                tuple(actual[k] for k in ('device','inode','uid','gid','mode')),
            'Appointed root not actual')
        c.need(root['writer_principal_ids']==[value['principal_ids'][role]],'Extra root writer')
    c.need(publishers['registry_authority_id']==value['principal_ids']['registry']
        and publishers['registry_root_id']==value['root_ids']['registry'],'Registry appointment')
    for role in s.ROLES:
        c.need(client[role+'_endpoint']==observed['roles'][role]['endpoint'],'Actual endpoint appointment')
    for role,kind in (('registry','REGISTRY_CUSTODIAN'),('observer','COMPLETION_OBSERVER'),('custody','CUSTODY')):
        if role!='registry':
            rows=[p for p in publishers['publishers'] if p['publisher_id']==value['principal_ids'][role]]
            c.need(len(rows)==1 and rows[0]['role']==kind
                   and rows[0]['signer_public_sha256']==value['signer_public_sha256'][role],'Signer appointment')
    c.need(publishers['registry_signer_public_sha256']==value['signer_public_sha256']['registry'],
           'Registry signer')
    # The independently selected register already exists. Never create a copied
    # "current" register or generate an authorizer/reviewer signing capability.
    rr=value['current_register']
    raw,_=c.read_protected(rr['path'],rr['maximum_bytes'])
    st=os.stat(rr['path'],follow_symlinks=False)
    c.need(tuple(rr[k] for k in ('device','inode','uid','gid','mode'))==
        (st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)),'Current register identity')
    c.need(c.decode(raw)=={'selection':publishers,'signature_hex':client['selection_signature_hex']},
           'Current authoritative register differs')
    return publishers

def role_config(role,appointment,observed,selection,config,controller,clock,s,c,
                completion_pin=None,selection_use=None):
    client=dict(appointment['client_config'])
    client['local_principal_id']=appointment['principal_ids'][role]
    identities={'controller':observed['controller'],'workload':observed['workload']}
    identities.update({name:row['process'] for name,row in observed['roles'].items()})
    endpoints={name:row['endpoint'] for name,row in observed['roles'].items()}
    return {'format':'forex.source-role-binding/1','role':role,'controller':controller,
        'prepared_sha256':c.digest(c.canonical(observed['roles'][role])) if role in s.ROLES else None,
        'source_selection':config['source_selection'],'test_deadline_utc':clock['stage_a_deadline_utc'],
        'clock_domain':observed['worker_ready']['clock_domain'],
        'clock_anchor_stamp':observed['worker_ready']['clock_anchor_stamp'],
        'current_register':appointment['current_register'],'client_config':client,
        'public_keys':appointment['public_keys'],
        'peers':peer_rows(role,endpoints,identities,s) if role in s.ROLES else [],
        'publish_routes':appointment['publish_routes'].get(role,[]),
        'completion_selection':completion_pin,'selection_use':selection_use,
        'original_clock':config['original_clock'],'source_manifest':selection['source_manifest'],
        'completion_material':selection['completion_material'],
        'signer_public_sha256':appointment['signer_public_sha256'].get(role)}

def retain_external(records,ports,allowed_kinds,root_id,c):
    from cas_forex_operational_contracts import protected as pr,common
    authority,files,registry,resolver,publishers,clock,base,_=ports
    result=[]
    c.need(type(records) is list and 0<len(records)<=128,'Setup record bound')
    for row in records:
        c.need(type(row) is dict and set(row)=={'record_hex','reference','publisher_envelope'},
               'Exact external signed record')
        raw=bytes.fromhex(row['record_hex']);ref=pr.validate('ProtectedRecordRef',row['reference']).payload()
        c.need(ref['record_kind'] in allowed_kinds and ref['root_id']==root_id,'External setup purpose/root')
        root,_,grant,now=authority.check_grant(ref,publishers,clock(),required_use='SOURCE_COMPLETION')
        if ref['record_kind']=='EXTERNAL_RELEASE_EVIDENCE':
            c.need(ref['purpose']=='release-evidence:original_clock_and_budget_binding_sha256'
                   and c.decode(raw).get('format')=='forex.original-source-test-clock/1',
                   'Source-only clock setup purpose')
        authority.validate_payload(raw,grant);authority.attest(ref,row['publisher_envelope'],publishers,now)
        envelope=pr.validate('ProtectedRecordEnvelope',row['publisher_envelope']).raw
        att={**ref,'object_id':common.digest(envelope),'sha256':common.digest(envelope),'bytes':len(envelope),
             'record_kind':'RECORD_ATTESTATION','purpose':'record-attestation'}
        attroot,_,_,_=authority.check_grant(att,publishers,clock(),required_use='AUTHORITY_METADATA')
        files.retain_exact(ref,raw,root,publishers,clock())
        files.retain_exact(att,envelope,attroot,publishers,clock())
        registration=registry.register_exact_record(raw,ref,row['publisher_envelope'],selection=publishers,now=clock())
        use={'reference':ref,'registration_sha256':common.digest(pr.validate('ProtectedRegistration',registration).raw),
             'required_use':'SOURCE_COMPLETION'}
        c.need(resolver.resolve(use,selection=publishers,now=clock())==raw,'External setup readback')
        result.append(use)
    return result

def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument('--selection',required=True);parser.add_argument('--selection-sha256',required=True)
    parser.add_argument('--appointment-fd',required=True,type=int)
    parser.add_argument('--registry-signer-fd',required=True,type=int)
    parser.add_argument('--observer-signer-fd',required=True,type=int)
    parser.add_argument('--custody-signer-fd',required=True,type=int)
    args=parser.parse_args(argv)
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    import launch_common as c
    import source_runtime_common as s
    descriptors=[args.appointment_fd,args.registry_signer_fd,args.observer_signer_fd,args.custody_signer_fd]
    c.need(len(set(descriptors))==4 and all(3<=fd<=1024 for fd in descriptors),'Separate selected private channels')
    for fd in descriptors:c.need(stat.S_ISFIFO(os.fstat(fd).st_mode),'Inherited private pipe required')
    os.umask(0o077)
    raw,_=c.read_protected(args.selection)
    c.need(c.digest(raw)==args.selection_sha256,'Controller pin')
    config=c.decode(raw);s.closed(config,s.CONTROLLER_FIELDS,'Closed controller selection')
    controller=admitted(config,raw,args.selection,args.selection_sha256,c)
    c.need(set(config['delivery_channels'])=={'appointment','registry','observer','custody'},
           'Exact delivery channels')
    for role in ('appointment','registry','observer','custody'):
        fd=args.appointment_fd if role=='appointment' else getattr(args,role+'_signer_fd')
        s.input_channel(fd,config['delivery_channels'][role])
    c.host_user_namespace()
    original=c.decode(c.pinned(config['bootstrap_record'])[0])
    roles={};owned=[];launcher=None
    deadline=LiveDeadline(c.Deadline(original['stage_a_deadline_utc']),
        config['controller_parent'],owned,args.selection,raw,c)
    c.need((c.utc(config['work_deadline_utc'])-c.utc(config['t0_utc'])).total_seconds()==13200
           and c.utc(config['t0_utc'])<=c.utc(original['bootstrap_started_utc'])
           <c.utc(original['stage_a_deadline_utc'])<=c.utc(config['work_deadline_utc'])
           and (c.utc(original['stage_a_deadline_utc'])-c.utc(original['bootstrap_started_utc'])).total_seconds()<=7200,
           'Original absolute limits')
    selection=c.decode(c.pinned(config['source_selection'])[0])
    s.load_source(selection)
    s.reviewed_runtime(selection,config['infrastructure_files'])
    for record in config['infrastructure_files']:c.pinned(record)
    runtime_directory=str(Path(__file__).resolve().parent)
    from source_test_launcher import verify_runtime
    runtime=c.decode(c.pinned(config['runtime_inventory'])[0])
    verify_runtime(runtime,c.decode(c.pinned(config['python_wheel_lock'])[0],False),c)
    # The root controller has no systemd private site bind. Use the same verified
    # immutable dependency tree explicitly; never install into host site paths.
    sys.path.insert(0,c.BASE+'/runtime/python-site')
    gid=config['reader_group_gid']
    artifact(c.BASE+'/receipts/source-controller.intent.json',
        {'selection_sha256':args.selection_sha256,'controller':controller,
         'test_deadline_utc':original['stage_a_deadline_utc']},c)
    try:
        ensure_reader_group(config,runtime,deadline,c,s)
        make_dir(s.IPC,0,gid,0o750,c)
        for role in s.ROLES:
            unit=unit_name(role);ensure_unit_unused(unit,deadline,c)
            startup=artifact(c.BASE+'/receipts/'+role+'-startup.json',
                {'format':'forex.source-role-startup/1','role':role,'controller':controller,
                 'source_selection':config['source_selection'],'test_deadline_utc':original['stage_a_deadline_utc'],
                 'reader_group_gid':gid,'unit':unit,'source_runtime_files':config['infrastructure_files']},c)
            # Precreate narrow children before systemd mount setup; ownership is
            # transferred only after the actual DynamicUser process is parked.
            make_dir(s.IPC+'/'+role,0,gid,0o2750,c)
            make_dir(s.IPC+'/'+role+'-records',0,gid,0o2750,c)
            err=open(c.BASE+'/receipts/'+role+'.stderr','xb',buffering=0)
            proc=subprocess.Popen(role_command(role,startup,int(deadline.remaining(5)),runtime_directory,c),
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'},
                start_new_session=True,bufsize=0)
            owned.append((unit,'forex-source-role-'+startup['sha256'],proc,err))
            parked=s.read_frame(proc.stdout.fileno(),deadline,32768)
            c.need(parked['format']=='forex.source-role-parked/1' and parked['role']==role,'Parked role')
            who=parked['process'];c.need(who==s.public_identity(who['pid']) and who['uid']>0,'Actual role process')
            mainpid=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=MainPID','--value'],
                check=True,capture_output=True,text=True,timeout=min(3,deadline.remaining(5))).stdout.strip()
            c.need(mainpid==str(who['pid']),'Role unit main process')
            from source_test_launcher import verify_effective_cgroup_properties
            verify_effective_cgroup_properties(unit,c,deadline)
            prepare=prepare_role_directories(role,who,gid,c,s)
            s.write_frame(proc.stdin.fileno(),prepare,deadline)
            prepared=s.read_frame(proc.stdout.fileno(),deadline,32768)
            c.need(prepared['format']=='forex.source-role-prepared/1' and prepared['process']==who
                   and prepared['published_root']==prepare['published_root']
                   and prepared['endpoint']==s.endpoint(s.IPC+'/'+role+'/rpc.sock',who),'Actual prepared listener')
            roles[role]={'process_handle':proc,'prepared':prepared}
        c.need(len({r['prepared']['process']['uid'] for r in roles.values()})==4,'Separate role UIDs')
        external_path=s.IPC+'/controller-records'
        make_dir(external_path,0,gid,0o2750,c);make_dir(external_path+'/objects',0,gid,0o2750,c)
        roles_receipt=artifact(c.BASE+'/receipts/source-roles-prepared.json',
            {'format':'forex.source-test-role-readiness/2','status':'ACTUAL_LISTENERS_PREPARED_NOT_ARMED',
             'test_deadline_utc':original['stage_a_deadline_utc'],'model_calls_limit':0,
             'reader_group_name':s.GROUP,'reader_group_gid':gid,
             'roles':{k:{'process':{n:v['prepared']['process'][n] for n in ('pid','start_ticks','uid')},
                         'prepared':v['prepared']} for k,v in roles.items()}},c)
        plan={k:config[k] for k in ('run_id','execution_mode','model_launch_allowed','model_inference_calls_limit',
            'stage_b_status','t0_utc','work_deadline_utc','bootstrap_record','source_selection',
            'runtime_inventory','python_wheel_lock','infrastructure_files','stop_proof','egress_receipt')}
        plan.update(format='forex.source-test-launch-plan/1',roles_receipt=roles_receipt,
            binding_path=c.BASE+'/receipts/source-test-deployment-binding.json',
            worker_path=runtime_directory+'/source_test_worker.py',python_site_directory=c.BASE+'/runtime/python-site')
        plan_pin=artifact(c.BASE+'/source-test-launch-plan.json',plan,c)
        admission={k:config[k] for k in ('owner_receipt','coordinator_receipt','budget_receipt','topology_acceptance')}
        admission.update(format='forex.source-test-controller-admission/1',status=config['status'],
            plan_sha256=plan_pin['sha256'],source_manifest_sha256=selection['source_manifest']['sha256'],
            runtime_inventory_sha256=config['runtime_inventory']['sha256'],worker_count=1,model_calls_limit=0,
            shared_first30days_ceiling_usd='15.00',work_deadline_utc=config['work_deadline_utc'],
            test_deadline_utc=original['stage_a_deadline_utc'],controller=controller,
            stop_proof_sha256=config['stop_proof']['sha256'],egress_receipt_sha256=config['egress_receipt']['sha256'],
            roles_receipt_sha256=roles_receipt['sha256'])
        admit=artifact(c.BASE+'/receipts/source-test-controller-admission.json',admission,c)
        le=open(c.BASE+'/receipts/source-launcher.stderr','xb',buffering=0)
        launcher=subprocess.Popen(['/usr/bin/python3','-I','-B',runtime_directory+'/source_test_launcher.py',
            '--plan',plan_pin['path'],'--plan-sha256',plan_pin['sha256'],
            '--admission',admit['path'],'--admission-sha256',admit['sha256']],
            stdout=subprocess.PIPE,stderr=le,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'},
            start_new_session=True,bufsize=0)
        owned.append((c.UNIT,'forex-source-tests-'+plan_pin['sha256'],launcher,le))
        parked=c.read_line(launcher.stdout.fileno(),deadline)
        c.need(parked['event']=='SOURCE_TEST_WORKER_PARKED','Workload not parked')
        ready_raw,_=c.read_protected(parked['ready_path']);c.need(c.digest(ready_raw)==parked['ready_sha256'],'Ready pin')
        ready=c.decode(ready_raw)
        observed={'format':'forex.source-test-startup-observations/1','controller':s.public_identity(),
            'workload':s.public_identity(ready['subject']['pid']),'worker_ready':ready,
            'roles':{k:v['prepared'] for k,v in roles.items()},'external_root':s.directory_identity(external_path),
            'controller_selection_sha256':args.selection_sha256,'plan_sha256':plan_pin['sha256']}
        artifact(c.BASE+'/receipts/source-startup-observations.json',observed,c)
        c.write_line(1,{'event':'APPOINTMENT_INPUT_REQUIRED','observations_sha256':c.digest(c.canonical(observed))},deadline)
        appointment=s.read_frame(args.appointment_fd,deadline)
        verify_appointment(appointment,observed,selection,config['appointment_authority'],c,s)
        def arm(role,completion_pin=None,selection_use=None):
            body=role_config(role,appointment,observed,selection,config,controller,original,s,c,completion_pin,selection_use)
            pin=artifact(c.BASE+'/receipts/'+role+'-binding.json',body,c)
            process=roles[role]['process_handle']
            s.write_frame(process.stdin.fileno(),{'format':'forex.source-role-arm/1','config':pin},deadline)
            if role!='current':
                descriptor=getattr(args,role+'_signer_fd')
                s.input_channel(descriptor,config['delivery_channels'][role])
                s.relay_signer_frame(descriptor,process.stdin.fileno(),deadline)
            armed=s.read_frame(process.stdout.fileno(),deadline,32768)
            c.need(armed=={'format':'forex.source-role-armed/1','role':role,
                'config_sha256':pin['sha256'],'prepared_sha256':body['prepared_sha256']},'Role did not arm')
            return armed
        armed={'current':arm('current'),'registry':arm('registry')}
        setup=role_config('controller',appointment,observed,selection,config,controller,original,s,c)
        setup_pin=artifact(c.BASE+'/receipts/setup-binding.json',setup,c)
        ports=s.make_ports(setup,c.canonical(setup),setup_pin,deadline,None)
        uses=retain_external(appointment['seed_records'],ports,
            {'COMMAND_PIN','PARSER_PIN','COLLECTION_INVENTORY','SOURCE_INVENTORY','EXTERNAL_RELEASE_EVIDENCE'},
            appointment['root_ids']['controller'],c)
        artifact(c.BASE+'/receipts/source-setup-registrations.json',uses,c)
        c.write_line(1,{'event':'COMPLETION_SELECTION_INPUT_REQUIRED',
            'registration_set_sha256':c.digest(c.canonical(uses))},deadline)
        s.input_channel(args.appointment_fd,config['delivery_channels']['appointment'])
        final=s.read_frame(args.appointment_fd,deadline)
        s.closed(final,{'format','registration_set_sha256','selection_record','bootstrap_config'},
                 'Final source binding')
        c.need(final['format']=='forex.source-test-final-binding/1'
            and final['registration_set_sha256']==c.digest(c.canonical(uses)),'Original setup refs')
        selection_uses=retain_external([final['selection_record']],ports,{'COMPLETION_SELECTION'},
            appointment['root_ids']['controller'],c)
        selection_raw=bytes.fromhex(final['selection_record']['record_hex'])
        completion_pin=artifact(c.BASE+'/source-completion-selection.json',c.decode(selection_raw),c)
        bootstrap=c.bootstrap_shape(final['bootstrap_config'])
        c.need(bootstrap['completion_selection']==completion_pin and bootstrap['selection_use']==selection_uses[0]
            and bootstrap['public_keys']==appointment['public_keys'],'Exact registered selection')
        expected_client=dict(appointment['client_config'])
        expected_client['local_principal_id']=appointment['principal_ids']['workload']
        c.need(bootstrap['custody_config']==expected_client,'Workload identity binding')
        from source_test_launcher import validate_binding
        validate_binding(bootstrap,ready,plan,selection,c.pinned(selection['source_manifest'])[0],
                         c.pinned(selection['completion_material'])[0],c.decode(c.pinned(roles_receipt)[0]),c)
        for role in ('observer','custody'):
            armed[role]=arm(role,completion_pin,selection_uses[0])
        armed_pin=artifact(c.BASE+'/receipts/source-roles-armed.json',
            {'format':'forex.source-roles-armed/1','roles':armed,
             'prepared_receipt_sha256':roles_receipt['sha256']},c)
        config_pin=artifact(c.BASE+'/source-test-config.json',bootstrap,c)
        artifact(plan['binding_path'],{'format':'forex.source-test-deployment-binding/2',
            'plan_sha256':plan_pin['sha256'],'admission_sha256':admit['sha256'],
            'ready_sha256':c.digest(ready_raw),'bootstrap_config':config_pin,'roles_armed':armed_pin},c)
        while launcher.poll() is None:
            deadline.remaining()
            c.need(c.process_identity(config['controller_parent']['pid'])==config['controller_parent'],'Outer controller withdrawn')
            for role in roles.values():c.need(role['process_handle'].poll() is None,'Role exited')
            time.sleep(min(.1,deadline.remaining()))
        c.need(launcher.returncode==0,'Source run incomplete')
        artifact(c.BASE+'/receipts/source-controller-exit.json',
            {'status':'LAUNCHER_EXIT_ZERO_ONLY','completion':'REQUIRES_ORIGINAL_VERIFIED_RECEIPT'},c)
        return 0
    finally:
        results=[]
        for unit,description,process,error in reversed(owned):
            stopped=kill_owned(unit,description,c)
            results.append({'unit':unit,'stop_requested_successfully':stopped})
            try:
                if process.poll() is None:os.killpg(process.pid,signal.SIGKILL)
            except (ProcessLookupError,OSError):pass
            finally:error.close()
        # Every owned unit gets an independent cleanup attempt even if one fails.
        # No receipt claims termination merely because a request was accepted.
        try:artifact(c.BASE+'/receipts/source-controller-cleanup.json',results,c)
        except Exception as exc:_logger.debug('Cleanup receipt write skipped: %s',exc)
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        print('{"status":"INCOMPLETE","component":"source-controller"}',file=sys.stderr)
        raise SystemExit(1)

