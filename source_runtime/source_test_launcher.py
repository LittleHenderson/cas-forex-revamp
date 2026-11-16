"""Root one-shot source-test supervisor/receipt producer; explicit future use only.

No credential/role-service provisioning, AWS, network download, or test import.
An independently accepted controller supplies the admission and dynamic binding.
This producer attests observed process identity; it does not issue owner approval.
"""
import argparse
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

PLAN_FIELDS = {'format','run_id','execution_mode','model_launch_allowed','model_inference_calls_limit',
    'stage_b_status','t0_utc','work_deadline_utc','bootstrap_record','source_selection',
    'runtime_inventory','python_wheel_lock','infrastructure_files',
    'stop_proof','egress_receipt','roles_receipt','binding_path','worker_path','python_site_directory'}

# The old unconditional source hold is replaced by a mandatory exact independent
# runtime-source review plus native admission. No default ready flag can release it.

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--plan',required=True)
    parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--admission',required=True)
    parser.add_argument('--admission-sha256',required=True)
    args = parser.parse_args()
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    import launch_common as c
    c.need(sys.platform == 'linux' and sys.version_info[:2] == (3,12) and os.geteuid() == 0,
           'Selected root Linux Python3.12 required')
    c.need(os.path.samefile('/proc/self/exe','/usr/bin/python3.12'),'Actual supervisor Python differs')
    c.host_user_namespace()
    plan_raw,plan_identity = c.read_protected(args.plan)
    c.need(c.HASH.fullmatch(args.plan_sha256) and c.digest(plan_raw) == args.plan_sha256,'Exact plan hash')
    plan = c.decode(plan_raw)
    c.need(type(plan) is dict and set(plan) == PLAN_FIELDS
           and plan['format'] == 'forex.source-test-launch-plan/1' and plan['run_id'] == c.RUN,'Plan shape')
    c.guards(plan)
    c.need((c.utc(plan['work_deadline_utc'])-c.utc(plan['t0_utc'])).total_seconds() == 13200,'Original global limit')
    original_raw,_ = c.pinned(plan['bootstrap_record']); original = c.decode(original_raw)
    start,end = original['bootstrap_started_utc'],original['stage_a_deadline_utc']
    c.need(original['run_id'] == c.RUN and c.utc(plan['t0_utc']) <= c.utc(start) < c.utc(end)
           <= c.utc(plan['work_deadline_utc']) and (c.utc(end)-c.utc(start)).total_seconds() <= 7200,
           'Original shared bootstrap/test limit')
    deadline = c.Deadline(end); deadline.remaining(10)
    selection_raw,_ = c.pinned(plan['source_selection']); selection = c.decode(selection_raw)
    c.need(selection['format'] == 'forex.source-test-infra-selection/1'
           and selection['status'] == 'INDEPENDENTLY_SOURCE_REVIEWED'
           and selection['phase'] == 'THIRTEEN_GROUP_SOURCE_COMPLETION_ONLY'
           and selection['parser_schema_shape'] == 'THREE_FORMAT_MAPPING','Corrected reviewed source required')
    manifest_raw,_ = c.pinned(selection['source_manifest'])
    c.need(c.digest(manifest_raw) == selection['source_manifest']['sha256'],
           'Exact independently reviewed source is required')
    manifest = c.decode(manifest_raw,False)
    material_raw,_ = c.pinned(selection['completion_material'])
    c.need(c.digest(material_raw) == selection['completion_material']['sha256'],
           'Selected completion material differs')
    c.pinned(selection['review_receipt'])
    verify_source(manifest,c)
    from source_runtime_common import load_source
    load_source(selection)
    from source_runtime_common import reviewed_runtime
    reviewed_runtime(selection, plan['infrastructure_files'])
    for record in plan['infrastructure_files']: c.pinned(record)
    infrastructure = {r['path']:r for r in plan['infrastructure_files']}
    here = str(Path(__file__).resolve())
    c.need(here in infrastructure and str(Path(__file__).resolve().parent/'launch_common.py') in infrastructure
           and plan['worker_path'] in infrastructure,'All infrastructure source must be pinned')
    c.under_base(plan['worker_path'])
    c.need(plan['binding_path'] == c.BASE+'/receipts/source-test-deployment-binding.json'
           and plan['python_site_directory'] == c.BASE+'/runtime/python-site','Fixed binding/runtime paths')
    c.need(not os.path.lexists(plan['binding_path'])
           and not os.path.lexists(c.BASE+'/receipts/source-test-launch-approval.json'), 'Preexisting release forbidden')
    runtime_raw,_ = c.pinned(plan['runtime_inventory']); runtime = c.decode(runtime_raw)
    lock_raw,_ = c.pinned(plan['python_wheel_lock']); wheel_lock = c.decode(lock_raw,False)
    verify_runtime(runtime,wheel_lock,c)
    c.need(args.admission == c.BASE+'/receipts/source-test-controller-admission.json'
           and c.HASH.fullmatch(args.admission_sha256),'Exact external admission path/hash')
    admission_raw,admission_identity = c.read_protected(args.admission)
    c.need(c.digest(admission_raw) == args.admission_sha256,'External admission hash differs')
    admission = c.decode(admission_raw)
    c.need(admission['format'] == 'forex.source-test-controller-admission/1'
           and admission['status'] == 'DIRECT_OWNER_AND_COORDINATOR_ACCEPTED'
           and admission['plan_sha256'] == args.plan_sha256
           and admission['source_manifest_sha256'] == c.digest(manifest_raw)
           and admission['runtime_inventory_sha256'] == c.digest(runtime_raw)
           and admission['worker_count'] == 1 and admission['model_calls_limit'] == 0
           and admission['shared_first30days_ceiling_usd'] == '15.00'
           and admission['work_deadline_utc'] == plan['work_deadline_utc']
           and admission['test_deadline_utc'] == end,'Exact upstream controller admission required')
    # Admission is written by the separately reviewed controller AFTER native
    # owner/coordinator acceptance. This module never writes or repairs it.
    controller = admission['controller']
    c.need(controller == c.process_identity(os.getppid()) and controller['uid'] == 0,'Live selected parent controller')
    for field in ('owner_receipt','coordinator_receipt','budget_receipt','topology_acceptance'):
        c.pinned(admission[field])
    for field in ('stop_proof','egress_receipt','roles_receipt'):
        c.need(admission[field+'_sha256'] == plan[field]['sha256'],'Admission evidence mismatch')
        c.pinned(plan[field])
    roles_raw,_ = c.pinned(plan['roles_receipt']); roles = c.decode(roles_raw)
    c.need(roles['format'] == 'forex.source-test-role-readiness/2'
           and roles['status'] == 'ACTUAL_LISTENERS_PREPARED_NOT_ARMED'
           and roles['test_deadline_utc'] == end and roles['model_calls_limit'] == 0,
           'Actual separately supervised roles required')
    c.need(set(roles['roles']) == {'current','registry','observer','custody'},'Exact role set')
    c.need(roles['reader_group_name'] == 'cas-fx-8e1a63c5-read'
           and type(roles['reader_group_gid']) is int and roles['reader_group_gid'] > 0,
           'Explicit source-evidence reader group required')
    for role in roles['roles'].values():
        c.need(role['process']['uid'] > 0 and c.process_identity(role['process']['pid']) == role['process'],
               'Selected role is not live')
    c.need(len({role['process']['uid'] for role in roles['roles'].values()}) == 4,'Distinct role UIDs required')
    # Full preflight may take time. Last time check precedes the sole service start.
    state = subprocess.run(['/usr/bin/systemctl','show',c.UNIT,'--property=LoadState','--value'],
                           check=True,capture_output=True,text=True,timeout=min(5,deadline.remaining(10))).stdout.strip()
    c.need(state == 'not-found','Existing unit cannot be reused')
    intent = {'format':'forex.source-test-guest-intent/1','run_id':c.RUN,
              'plan_sha256':args.plan_sha256,'controller_admission_sha256':c.digest(admission_raw),
              'test_deadline_utc':end,'work_deadline_utc':plan['work_deadline_utc']}
    c.create_retained(c.BASE+'/receipts/guest-launch.intent.json',intent)
    remaining = math.floor(deadline.remaining(5))
    c.need(remaining > 0,'No service time remains')
    command = systemd_command(plan,remaining,args.plan,args.plan_sha256,c)
    output_path = c.BASE+'/receipts/source-test-service.stdout'
    error_path = c.BASE+'/receipts/source-test-service.stderr'
    # Both pipes are drained with byte bounds into retained evidence.
    error_fd = os.open(error_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    process = None
    try:
        process = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'},start_new_session=True,bufsize=0)
        ready = read_ready(process,error_fd,deadline,c)
        validate_ready(ready,plan,roles,c,deadline,args.plan,args.plan_sha256)
        ready_raw,_ = c.create_retained(c.BASE+'/receipts/source-test-worker-ready.json',ready)
        c.write_line(1,{'event':'SOURCE_TEST_WORKER_PARKED','ready_sha256':c.digest(ready_raw),
                        'ready_path':c.BASE+'/receipts/source-test-worker-ready.json'},deadline)
        # The existing root controller now appoints actual peer/UID/inode values,
        # freezes the closed bootstrap config, and writes the exact binding. No
        # application execution occurs while waiting and the original timer runs.
        while not os.path.lexists(plan['binding_path']):
            deadline.remaining(5)
            c.need(process.poll() is None and c.process_identity(controller['pid']) == controller,'Controller/worker exited')
            time.sleep(min(0.1,deadline.remaining(5)))
        binding_raw,_ = c.read_protected(plan['binding_path']); binding = c.decode(binding_raw)
        c.need(set(binding) == {'format','plan_sha256','admission_sha256','ready_sha256','bootstrap_config','roles_armed'}
               and binding['format'] == 'forex.source-test-deployment-binding/2'
               and binding['plan_sha256'] == args.plan_sha256
               and binding['admission_sha256'] == c.digest(admission_raw)
               and binding['ready_sha256'] == c.digest(ready_raw),'Exact runtime binding required')
        config_raw,_ = c.pinned(binding['bootstrap_config']); config = c.bootstrap_shape(c.decode(config_raw))
        armed = c.decode(c.pinned(binding['roles_armed'])[0])
        c.need(armed['format'] == 'forex.source-roles-armed/1'
               and armed['prepared_receipt_sha256'] == plan['roles_receipt']['sha256']
               and set(armed['roles']) == {'current','registry','observer','custody'},
               'All prepared roles must be armed before release')
        for name, row in armed['roles'].items():
            c.need(row['format'] == 'forex.source-role-armed/1' and row['role'] == name
                   and row['prepared_sha256'] == c.digest(c.canonical(roles['roles'][name]['prepared'])),
                   'Role armed against wrong preparation')
            role_raw,_ = c.read_protected(c.BASE+'/receipts/'+name+'-binding.json')
            c.need(c.digest(role_raw) == row['config_sha256'], 'Role binding replaced')
        c.bootstrap_argv(binding['bootstrap_config'])
        validate_binding(config,ready,plan,selection,manifest_raw,material_raw,roles,c)
        unchanged,_ = c.read_protected(args.plan,expected=plan_identity)
        c.need(unchanged == plan_raw,'Plan changed during preparation')
        unchanged,_ = c.read_protected(args.admission,expected=admission_identity)
        c.need(unchanged == admission_raw,'Admission withdrawn')
        deadline.remaining(5)
        receipt = approval_receipt(config_raw,config,ready,manifest_raw,c)
        approval_raw,_ = c.create_retained(config['approval_path'],receipt)
        c.write_line(process.stdin.fileno(),{'format':'forex.source-test-worker-release/1',
            'config':binding['bootstrap_config'],'approval_sha256':c.digest(approval_raw),
            'ready_sha256':c.digest(ready_raw)},deadline)
        process.stdin.close()
        retain_output(process,output_path,error_fd,deadline,controller,roles,c)
        c.need(process.wait(timeout=min(1,deadline.remaining())) == 0,'Source completion failed')
        c.create_retained(c.BASE+'/receipts/source-test-service-exit.json',
            {'status':'PROCESS_EXIT_ZERO_ONLY','tests':'REQUIRE_INDEPENDENT_COMPLETION_RECEIPT',
             'observed_utc':c.stamp(),'approval_sha256':c.digest(approval_raw)})
        return 0
    finally:
        os.close(error_fd)
        # This does not revoke independent EC2 stop authority or delete receipts.
        # A host error must stop the whole known unit, not just systemd-run.
        if process is not None:
            owned = subprocess.run(['/usr/bin/systemctl','show',c.UNIT,'--property=Description','--value'],
                check=False,capture_output=True,text=True,timeout=3)
            if owned.returncode == 0 and owned.stdout.strip() == 'forex-source-tests-'+args.plan_sha256:
                subprocess.run(['/usr/bin/systemctl','kill','--kill-whom=all','--signal=SIGKILL',c.UNIT],
                               check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGKILL)

def verify_source(manifest,c):
    selected = {}
    for row in manifest['files']:
        name = row['path']
        c.need(type(name) is str and not name.startswith('/') and '\\' not in name
               and '..' not in Path(name).parts and name not in selected,'Source member path')
        c.need(not any(x.lower() in {'.private','.aws','.git','.codex'} for x in name.split('/')),'Excluded source')
        c.pinned({**row,'path':c.BASE+'/source/'+name})
        selected[name] = row
    actual = set()
    for directory,dirs,names in os.walk(c.BASE+'/source',followlinks=False):
        c.need(not any(os.path.islink(os.path.join(directory,x)) for x in dirs),'Source directory symlink')
        actual.update(Path(directory,x).relative_to(c.BASE+'/source').as_posix() for x in names)
    c.need(actual == set(selected) and 'source_test_bootstrap.py' in selected,'Complete source membership')

def verify_runtime(runtime,lock,c):
    c.need(runtime['format'] == 'forex.source-test-runtime-inventory/1'
           and runtime['status'] == 'ACTUAL_BYTES_VERIFIED' and runtime['python_version'].startswith('3.12.')
           and runtime['node_version'] == 'v24.21.0','Actual selected runtime inventory required')
    c.need([(x['project'],x['version']) for x in lock['wheels']] ==
           [('cryptography','50.0.2'),('cffi','2.0.0'),('pycparser','2.23')],'Fixed dependency versions')
    c.need([x['sha256'] for x in lock['wheels']] == [
        '4061c0079120205fb760c58acab6443e217307dcf05e3702cf970e0689972856',
        '3e17ed538242334bf70832644a32a7aae3d83b57567f9fd60a26257e992b79ba',
        'e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934'],
        'Official wheel archive pins differ')
    rows = {}
    for wheel in lock['wheels']:
        for row in wheel['members']:
            path = c.BASE+'/runtime/python-site/'+row['path']
            c.need(path not in rows and not path.endswith('.pth'),'Runtime overlap/startup hook')
            rows[path] = {**row,'path':path}
    c.need(runtime['python_site_files'] == [rows[k] for k in sorted(rows)],'Exact wheel member closure')
    for row in runtime['files'] + runtime['python_site_files']: c.pinned(row,512*1024*1024)
    seen = set()
    for directory,dirs,names in os.walk(c.BASE+'/runtime/python-site',followlinks=False):
        c.need(not any(os.path.islink(os.path.join(directory,x)) for x in dirs),'Python-site directory symlink')
        seen.update(os.path.join(directory,x) for x in names)
    c.need(seen == set(rows),'Unexpected Python-site contents')
    c.need({'/usr/bin/python3.12','/usr/bin/systemd-run','/usr/bin/systemctl'} <=
           {x['path'] for x in runtime['files']},'Host command pins required')
    c.need(os.path.realpath('/usr/bin/python3') == '/usr/bin/python3.12','Unexpected Python alias')
    c.need(runtime['isolated_site_path'] == '/usr/local/lib/python3.12/dist-packages'
           and runtime['isolated_site_precedes_system_distribution'] is True,
           'Actual isolated import-path observation required')

REQUIRED_CGROUP_PROPERTIES = {
    'MemoryHigh': '1536M',
    'MemoryMax': '2048M',
    'MemorySwapMax': '0',
    'CPUQuota': '200%',
    'TasksMax': '256',
    'LimitNPROC': '256',
    'LimitNOFILE': '1024',
    'OOMPolicy': 'kill',
    'KillMode': 'control-group',
}

SYSTEMCTL_CGROUP_QUERY = (
    'MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,CPUQuota,'
    'TasksMax,LimitNPROC,LimitNOFILE,OOMPolicy,KillMode'
)

_EFFECTIVE_EXACT_VALUES = {
    'MemoryHigh': frozenset({'1610612736', '1536M'}),
    'MemoryMax': frozenset({'2147483648', '2048M'}),
    'MemorySwapMax': frozenset({'0', '0B'}),
    'TasksMax': frozenset({'256'}),
    'LimitNPROC': frozenset({'256'}),
    'LimitNOFILE': frozenset({'1024'}),
    'OOMPolicy': frozenset({'kill'}),
    'KillMode': frozenset({'control-group'}),
}

_EFFECTIVE_CPU_QUOTA_USEC = frozenset({'2s', '2000ms', '2000000', '2000000us', '200%'})

def parse_systemctl_properties(output,c):
    c.need(type(output) is str and bool(output.strip()),'Empty systemctl cgroup property output')
    parsed = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        c.need('=' in line,'Malformed systemctl property line')
        key,value = line.split('=',1)
        key,value = key.strip(),value.strip()
        c.need(bool(key) and key not in parsed,'Duplicate or empty systemctl property key')
        parsed[key] = value
    return parsed

def verify_effective_cgroup_properties(unit,c,deadline):
    result = subprocess.run(['/usr/bin/systemctl','show',unit,'--property='+SYSTEMCTL_CGROUP_QUERY],
        check=True,capture_output=True,text=True,timeout=min(3,deadline.remaining(5)))
    props = parse_systemctl_properties(result.stdout,c)
    for key,allowed in _EFFECTIVE_EXACT_VALUES.items():
        c.need(props.get(key) in allowed,'Effective unit property '+key+' missing or mismatched')
    raw_quota = props.get('CPUQuota')
    raw_usec = props.get('CPUQuotaPerSecUSec')
    if raw_quota not in (None,'','[not set]'):
        c.need(raw_quota == '200%','Effective unit CPUQuota mismatched')
    if raw_usec not in (None,'','[not set]'):
        c.need(raw_usec in _EFFECTIVE_CPU_QUOTA_USEC,'Effective unit CPUQuotaPerSecUSec mismatched')
    c.need(raw_quota == '200%' or raw_usec in _EFFECTIVE_CPU_QUOTA_USEC,
           'Effective unit CPUQuota ceiling missing')

def systemd_command(plan,seconds,path,pin,c):
    properties = {'Description':'forex-source-tests-'+pin,'Type':'exec','Restart':'no','RuntimeMaxSec':str(seconds),'TimeoutStopSec':'1',
        'KillMode':'control-group','SendSIGKILL':'yes','DynamicUser':'yes','NoNewPrivileges':'yes',
        'UMask':'0077','CapabilityBoundingSet':'','AmbientCapabilities':'','PrivateNetwork':'yes',
        'PrivateDevices':'yes','PrivateTmp':'yes','ProtectSystem':'strict','ProtectHome':'yes',
        'ProtectProc':'default','ProcSubset':'all','ProtectKernelTunables':'yes','ProtectKernelModules':'yes',
        'ProtectKernelLogs':'yes','ProtectControlGroups':'yes','RestrictSUIDSGID':'yes',
        'RestrictNamespaces':'yes','LockPersonality':'yes','RestrictAddressFamilies':'AF_UNIX AF_INET AF_INET6',
        'InaccessiblePaths':'-/root -/home -/media -/mnt',
        'ReadOnlyPaths':c.BASE,'StateDirectory':c.UNIT,'StateDirectoryMode':'0700',
        'BindReadOnlyPaths':plan['python_site_directory']+':/usr/local/lib/python3.12/dist-packages',
        'SupplementaryGroups':'cas-fx-8e1a63c5-read','Environment':'HOME=/tmp',
        **REQUIRED_CGROUP_PROPERTIES}
    command = ['/usr/bin/systemd-run','--unit='+c.UNIT,'--wait','--pipe','--quiet']
    command += ['--property='+key+'='+value for key,value in properties.items()]
    return command+['/usr/bin/python3','-I','-B',plan['worker_path'],'--plan',path,'--plan-sha256',pin]

def validate_ready(ready,plan,roles,c,deadline,plan_path,plan_sha256):
    c.need(type(ready) is dict and set(ready) == {'format','subject','clock_domain','clock_anchor_stamp',
           'directories','isolation','supplementary_gids','state_directory'} and ready['format'] == 'forex.source-test-worker-ready/1','Worker ready shape')
    subject = ready['subject']
    c.need(subject['uid'] > 0 and c.process_identity(subject['pid']) == subject
           and subject['uid'] not in {x['process']['uid'] for x in roles['roles'].values()},'Actual separate worker identity')
    c.need(roles['reader_group_gid'] in ready['supplementary_gids'],'Actual evidence-reader group absent')
    pid = subprocess.run(['/usr/bin/systemctl','show',c.UNIT,'--property=MainPID','--value'],
        check=True,capture_output=True,text=True,timeout=min(3,deadline.remaining(5))).stdout.strip()
    c.need(pid == str(subject['pid']),'Subject is not the exact unit main process')
    verify_effective_cgroup_properties(c.UNIT,c,deadline)
    expected = ['/usr/bin/python3','-I','-B',plan['worker_path'],'--plan',plan_path,
                '--plan-sha256',plan_sha256]
    cmdline = Path('/proc/'+pid+'/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
    c.need(cmdline == [x.encode() for x in expected],'Unexpected subject executable argv')
    c.need(set(ready['directories']) == {'attempt','capture','temporary'},'Worker state shape')
    c.need(ready['state_directory'] in {'/var/lib/'+c.UNIT,'/var/lib/private/'+c.UNIT},'Actual state path')
    for leaf,row in ready['directories'].items():
        c.need(row['path'] == ready['state_directory']+'/'+leaf and row['uid'] == subject['uid']
               and row['mode'] == 0o700,'Worker state binding')
        st = os.stat('/proc/'+pid+'/root'+row['path'],follow_symlinks=False)
        c.need((st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)) ==
               tuple(row[k] for k in ('device','inode','uid','gid','mode')),'Actual state identity differs')
    domain,now = c.observe_pair()
    c.need(domain == ready['clock_domain'] and c.utc(ready['clock_anchor_stamp']['utc']) <= c.utc(now['utc'])
           and ready['clock_anchor_stamp']['boottime_ns'] <= now['boottime_ns'],'Actual paired anchor differs')

def validate_binding(config,ready,plan,selection,manifest_raw,material_raw,roles,c):
    c.need(config['clock_domain'] == ready['clock_domain'] and config['clock_anchor_stamp'] == ready['clock_anchor_stamp']
           and config['work_started_utc'] == plan['t0_utc'] and config['work_deadline_utc'] == plan['work_deadline_utc']
           and config['attempt_directory'] == ready['directories']['attempt']
           and config['capture_directory'] == ready['directories']['capture']['path'],'Immutable actual binding differs')
    c.need(config['source_manifest'] == selection['source_manifest'] and config['completion_material'] == selection['completion_material'],
           'Source selection substituted')
    c.need(c.pinned(config['source_manifest'])[0] == manifest_raw and c.pinned(config['completion_material'])[0] == material_raw,
           'Source selection bytes changed')
    original = c.decode(c.pinned(config['original_clock'])[0])
    outer = c.decode(c.pinned(plan['bootstrap_record'])[0])
    c.need(set(original) == {'format','bootstrap_started_utc','test_deadline_utc'}
           and original['format'] == 'forex.original-source-test-clock/1'
           and original['bootstrap_started_utc'] == outer['bootstrap_started_utc']
           and original['test_deadline_utc'] == outer['stage_a_deadline_utc'],'Original source-only clock differs')
    c.pinned(config['completion_selection'])
    for name in ('current','registry','observer','custody'):
        endpoint = config['custody_config'][name+'_endpoint']; role = roles['roles'][name]
        c.need((endpoint['peer_pid'],endpoint['peer_uid'],endpoint['peer_start_ticks']) ==
               tuple(role['process'][k] for k in ('pid','uid','start_ticks')),'Role endpoint differs')
    c.need(config['environment'].get('TMPDIR') == ready['directories']['temporary']['path']
           and c.digest(c.canonical(config['environment'])) == config['environment_profile_sha256'],
           'Child environment binding differs')

def approval_receipt(config_raw,config,ready,manifest_raw,c):
    subject = c.process_identity(ready['subject']['pid'])
    c.need(subject == ready['subject'] and subject['uid'] > 0,'Subject changed before receipt')
    original_raw,_ = c.pinned(config['original_clock'])
    from source_test_namespace_observer import observe_host_user_namespace
    supervisor = c.process_identity(os.getpid())
    proof = observe_host_user_namespace(subject=subject, supervisor=supervisor,
        clock_domain=config['clock_domain'], clock_anchor_stamp=config['clock_anchor_stamp'])
    return {'format':'forex.source-test-launch-approval/2','decision':'ALLOW_SOURCE_TESTS_ONCE',
        'invocation_id':'source-tests-'+c.digest(config_raw)[:32],'config_sha256':c.digest(config_raw),
        'source_manifest_sha256':c.digest(manifest_raw),'original_clock_sha256':c.digest(original_raw),
        'clock_domain':config['clock_domain'],'clock_anchor_stamp':config['clock_anchor_stamp'],
        'work_started_utc':config['work_started_utc'],'work_deadline_utc':config['work_deadline_utc'],
        'subject':subject,'supervisor':supervisor,'observed_at_utc':proof['observed_at_utc'],
        'host_user_namespace_proof':proof}

def write_all(fd,data,c):
    view = memoryview(data)
    while view:
        written = os.write(fd,view); c.need(written > 0,'Output write failed'); view = view[written:]

def read_ready(process,error_fd,deadline,c):
    import select
    raw = bytearray(); errors = 0
    streams = [process.stdout,process.stderr]
    while True:
        available,_,_ = select.select(streams,[],[],min(0.25,deadline.remaining(5)))
        for stream in available:
            if stream is process.stderr:
                data = os.read(stream.fileno(),65536)
                if not data: streams.remove(stream); continue
                errors += len(data); c.need(errors <= 4*1024*1024,'Preparation stderr bound')
                write_all(error_fd,data,c)
            else:
                data = os.read(stream.fileno(),1); c.need(data,'Worker exited before ready')
                if data == b'\n': return c.decode(bytes(raw))
                raw.extend(data); c.need(len(raw) <= 16384,'Worker ready frame bound')

def retain_output(process,path,error_fd,deadline,controller,roles,c):
    import select
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    totals = {process.stdout:0,process.stderr:0}; streams = list(totals)
    try:
        while streams:
            deadline.remaining(5)
            c.need(c.process_identity(controller['pid']) == controller,'Controller withdrawn')
            for role in roles['roles'].values():
                c.need(c.process_identity(role['process']['pid']) == role['process'],'Role exited')
            ready,_,_ = select.select(streams,[],[],min(0.25,deadline.remaining(5)))
            if not ready: continue
            for stream in ready:
                data = os.read(stream.fileno(),65536)
                if not data: streams.remove(stream); continue
                totals[stream] += len(data); c.need(totals[stream] <= 4*1024*1024,'Bootstrap output bound')
                write_all(fd if stream is process.stdout else error_fd,data,c)
        os.fsync(fd)
        os.fsync(error_fd)
    finally: os.close(fd)

if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception:
        print('{"status":"INCOMPLETE","component":"root-source-test-supervisor"}',file=sys.stderr)
        raise SystemExit(1)
