"""Trusted controller adapter; all future state and durable ledgers stay here.

The decision role gets a current packet and narrowly scoped evidence RPC. It
cannot open a database or appoint a callback, file, principal or future event.
"""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import logging
import os
from pathlib import Path
import socket
import subprocess  # nosec B404: isolated Stage B worker spawns pinned /usr/bin/python3 with close_fds and zero shell

from ..contracts import canonical_bytes, content_digest, DecisionRequest
from ..core.storage import decode
from ..operator.model import InferenceReply
from ..operator.ollama_backend import OllamaRuntimePin
from ..operator.runtime_observer import LinuxRuntimeObserver, SupervisorSpec
from .custody_protocol import envelope, validate_message, ReleaseLedger
from dataclasses import replace
import time
from ..operator.model_evidence import ObserverAuthorizedModelStore
from ..operator.ollama_backend import ENDPOINT
from .generation_transport import GenerationClient, need, verify_generation_transport, pending_ordering
from .model_evidence_bridge import ModelDecisionReader
from .observed_model_ports import ObservedModelPorts
from .remote_pending import ControllerDueEvents
from .role_channel import RoleChannel

_logger = logging.getLogger(__name__)

# Finding [4]: DECISION_RUNNER worker may NEVER author model, runtime, or transport observation evidence.
RUNNER_KINDS = frozenset()
REQUIRED_OBSERVER_RECEIPT_PREFIXES = (
    'token-proof-',
    'runtime-before-',
    'runtime-after-',
    'generation-attempt-',
    'generation-sent-',
    'generation-capture-',
    'generation-http-',
    'inference-',
)


def _runner_alive(pid: int) -> bool:
    try:
        status = Path('/proc', str(pid), 'status').read_text()
    except FileNotFoundError:
        return False
    return 'State:	Z' not in status


def _runner_in_children(ollama_pid: int, pid: int, proc_root: Path) -> bool:
    try:
        for task in (proc_root / str(ollama_pid) / 'task').iterdir():
            try:
                if str(pid) in (task / 'children').read_text().split():
                    return True
            except FileNotFoundError as exc:
                _missing_task = str(exc)
                continue
    except FileNotFoundError:
        return False
    return False


class _ControllerGenerationClient(GenerationClient):
    """Controller-owned loopback generation socket executing inside the trusted observer boundary (Finding [4])."""

    def __init__(self, *, owner, request_id, **kwargs):
        super().__init__(**kwargs)
        self.owner = owner
        self.request_id = request_id

    def pending_mode(self):
        return 'CONTROLLER_DUE_ACK'

    def pending_changes(self, connection, deadline):
        sent = self.store.require_observer_provenance('generation-sent-' + self.key)
        attempt = self.store.require_observer_provenance('generation-attempt-' + self.key)
        token = self.store.require_observer_provenance('token-proof-' + self.key)
        base = {
            'generation_attempt_id': attempt['receipt_id'],
            'generation_http_id': 'generation-http-' + self.key,
            'invocation_sha256': self.key,
            'generation_body_sha256': sent['payload']['body_sha256'],
            'transport_sent_receipt_sha256': sent['sha256'],
        }
        submitted_payload = {
            **base,
            'transport_capture_binding_sha256': content_digest({'clock_id': self.clock_id, 'invocation_sha256': self.key}),
            'preflight_receipt_sha256': token['sha256'],
            'clock_binding_sha256': content_digest({'clock_id': self.clock_id, 'run_id': self.store.run_id}),
        }
        submitted = envelope(
            'GENERATION_SUBMITTED',
            submitted_payload,
            binding=self.owner.binding,
            request_id=self.request_id,
            sequence=self.owner.next_sequence(),
            now=self.clock(),
        )
        need(self.owner.due.submitted(submitted) is True, 'complete-send receipt was not retained')
        for index in range(9):
            need(self.monotonic() < deadline, 'pending RPC window expired')
            readable, _, failed = self.select([connection], [], [connection], 0)
            before_ready = bool(readable or failed)
            start = self.stamp()
            ack, error = None, None
            try:
                ack = self.owner.due.due({
                    'submitted_sha256': content_digest(submitted),
                    'index': index,
                    'before_response_ready': before_ready,
                    'started': start,
                })
            except Exception as exc:
                error = type(exc).__name__
            completed = self.stamp()
            readable, _, failed = self.select([connection], [], [connection], 0)
            after_ready = bool(readable or failed)
            checked = self.stamp()
            if ack is not None and ack['status'] == 'NO_DUE_EVENT':
                break
            row = self.record(
                'pending-' + str(index),
                'MODEL_TRANSPORT_PENDING_WINDOW',
                {
                    'index': index,
                    'before_response_ready': before_ready,
                    'after_response_ready': after_ready,
                    'started': start,
                    'completed': completed,
                    'after_check': checked,
                    'controller_ack_sha256': ack['ack_sha256'] if ack and ack['status'] == 'APPLIED' else None,
                    'error_type': error,
                },
            )
            self.owner.due.window(row)
            if before_ready or after_ready or error is not None or not ack or ack['status'] != 'APPLIED':
                break


class _ControllerObservedPorts(ObservedModelPorts):
    """Controller-owned preflight/generation port bound to the private observer_key (Finding [4])."""

    def __init__(self, *, owner, **kwargs):
        super().__init__(**kwargs)
        self.owner = owner

    def count(self, invocation, request, pin):
        key = content_digest(invocation)
        need(key not in self._deadlines, 'preflight is one-shot')
        deadline = min(self.store.deadline, request.absolute_deadline, self.owner._invocation_deadline)
        self._deadlines[key] = deadline
        return self.preflight.count(invocation, replace(request, absolute_deadline=deadline), pin)

    def post(self, request):
        need(self._active is not None, 'generation lacks preflight binding')
        invocation, expected = self._active
        self._active = None
        need(request == expected and request.endpoint == ENDPOINT, 'generation request changed')
        self.runtime.require_same(self._token(invocation)['runtime'])
        key = content_digest(invocation)
        bounded = replace(request, absolute_deadline=min(request.absolute_deadline, self._deadlines[key]))
        client = _ControllerGenerationClient(
            owner=self.owner,
            request_id=json.loads(invocation.packet_json)['request_id'],
            store=self.store,
            phase=self.phase,
            invocation_sha256=key,
            request_sha256=invocation.request_sha256,
            clock=self.clock,
        )
        response, _ = self.exchange.post(invocation, bounded, operation='generation', client=client)
        return response


class IsolatedController:
    def __init__(self, *, cfg, out, window, store, journal, scope, pending_changes, clock):
        self.cfg,self.out,self.window,self.store=cfg,Path(out).resolve(),window,store
        self.journal,self.scope,self.plans,self.clock=journal,scope,pending_changes,clock
        self.child=self.channel=None;self.active=None;self.sequence=0;self.source_binding=None
        self.spent_requests=set();self.gates={};self.readers={};self.verifiers={};self.executors={}
        self._observer_key = os.urandom(32)
        if callable(getattr(self.store, 'bind_observer_key', None)):
            self.store.bind_observer_key(self._observer_key)
        self._observer_store = ObserverAuthorizedModelStore(self.store, self._observer_key)
        self._previous_runner = None
        self._invocation_deadline = self.window.end
        self._preflight_done_key = None
        self._generate_allowed_key = None

    def next_sequence(self):
        self.sequence+=1;return self.sequence

    def start(self):
        """Call before controller reads private documents. No preexec callbacks."""
        from role_boundary import identity, role_observation
        from approved_model_driver import runtime_libraries
        from isolation_release import consume_external_release
        source=Path(self.cfg['source_directory']);base=source.parent
        def file_identity(path):
            need(not Path(path).is_symlink(),'runtime/source link changed')
            s=Path(path).stat()
            return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        self.file_identity=file_identity
        self.asset_identity={r['path']:file_identity(r['path']) for r in [*self.cfg['files'],self.cfg['python_runtime']]}
        runner=self.out/'role-runner';model=self.out/'role-model'
        for p in (runner,model,model/'home',model/'tmp'):
            p.mkdir(mode=0o700)
        extra_public=[p for p in ('/dev/urandom','/dev/random','/etc/localtime','/usr/share/zoneinfo') if Path(p).exists()]
        public=list(dict.fromkeys(str(Path(p).resolve()) for p in [str(source),str(base/'runtime'),str(base/'models'),'/usr/lib','/proc','/sys','/etc/ld.so.cache',*extra_public]))
        extra_exec=[str(Path(p).resolve()) for p in ('/lib64/ld-linux-x86-64.so.2','/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2') if Path(p).exists()]
        execute=list(dict.fromkeys([str(Path('/usr/bin/python3').resolve()),self.cfg['ollama_binary'],self.cfg['runner_binary'],*extra_exec]))
        model_execute=list(dict.fromkeys([self.cfg['ollama_binary'],self.cfg['runner_binary'],*extra_exec]))
        policy={'read':public,'execute':execute,'write':[str(runner),str(model),'/dev/null']}
        model_policy={'read':[p for p in public if p!=str(source)],'execute':model_execute,
                      'write':[str(model),'/dev/null']}
        clean={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
        model_env={**clean,'HOME':str(model/'home'),'TMPDIR':str(model/'tmp'),'OLLAMA_HOST':'127.0.0.1:11434',
            'OLLAMA_NO_CLOUD':'1','OLLAMA_NOPRUNE':'1','OLLAMA_MODELS':self.cfg['models_directory'],'OLLAMA_NUM_PARALLEL':'1',
            'OLLAMA_MAX_LOADED_MODELS':'1','OLLAMA_KEEP_ALIVE':'0','OLLAMA_LOAD_TIMEOUT':'180s',
            'LLAMA_ARG_LOAD_MODE':'mmap','LLAMA_ARG_REPACK':'0',
            'LD_LIBRARY_PATH':runtime_libraries(self.cfg,'ollama_library_directories')}
        key=os.urandom(32)
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        left.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        right.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        read_fd,write_fd=os.pipe()
        boot={'parent':identity(os.getpid()),'policy':policy,'probe_paths':self.cfg['isolation']['probe_paths'],
            'boot_id':self.cfg['isolation']['boot_id'],
            'source_directory':str(source),'selection_schema_path':self.cfg.get('selection_schema_path','docs/contracts/decision-selection.schema.json'),'role_files':self.cfg['role_files'],'run_id':self.cfg['run_id'],
            'deadline':self.window.end.isoformat(),'channel_id':self.cfg['isolation']['channel_id'],
            'channel_key':key.hex(),'prompt_version':self.cfg['prompt_version'],'seed':self.cfg['seed'],
            'clean_environment':clean,'model_bootstrap':{'policy':model_policy,'binary':self.cfg['ollama_binary'],
                'environment':model_env,'cwd':str(model),'probe_paths':self.cfg['isolation']['probe_paths'],
                'boot_id':self.cfg['isolation']['boot_id']}}
        try:
            self.child=subprocess.Popen(['/usr/bin/python3','-B',str(source/'isolated_decision_worker.py'),  # nosec B603: pinned absolute /usr/bin/python3 argv with sanitized environment and no shell
                '--bootstrap-fd',str(read_fd),'--channel-fd',str(right.fileno())],cwd=runner,env=clean,
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                close_fds=True,pass_fds=(read_fd,right.fileno()),start_new_session=True)
        finally:os.close(read_fd);right.close()
        peer=identity(self.child.pid)
        self.channel=RoleChannel(left,key=key,channel_id=boot['channel_id'],peer_pid=peer['pid'],
            peer_start_ticks=peer['start_ticks'],deadline=self.window.end,clock=self.clock)
        with os.fdopen(write_fd,'wb') as handle:handle.write(canonical_bytes(boot))
        method,ready=self.channel.receive();need(method=='ROLE_READY','isolated roles not ready')
        self.pin=decode(canonical_bytes(ready['pin']).decode(),OllamaRuntimePin)
        self.supervisor=decode(canonical_bytes(ready['supervisor']).decode(),SupervisorSpec)
        need(self.supervisor.ollama_pid==ready['model']['role']['pid']
             and self.supervisor.ollama_start_ticks==ready['model']['role']['start_ticks'], 'model wrapper identity changed')
        need(json.loads(canonical_bytes(self.supervisor.files))==self.cfg['role_files'],
             'role report changed pinned model/runtime files')
        self.roles={'CUSTODY_CONTROLLER':role_observation(self.cfg['isolation']['boot_id']),'DECISION_RUNNER':ready['runner']['role'],
                    'MODEL_SERVICE':{**ready['model']['role'],'exe':self.cfg['ollama_binary']}}
        import ctypes, platform
        if platform.system()=='Linux':
            need(ctypes.CDLL(None,use_errno=True).prctl(4,0,0,0,0)==0,'controller non-dumpable guard failed')
        self.ready=ready
        self.journal.append('role-setup','ROLE_SETUP_OBSERVATION',self.scope,
            {'roles':self.roles,'raw':ready,'policy':policy,'model_policy':model_policy},now=self.clock())
        from approved_model_driver import write_new
        write_new(self.out/'role-setup-observation.json',{'roles':self.roles,'raw':ready,
            'policy':policy,'model_policy':model_policy,'channel_id':boot['channel_id']})
        # Externally selected observer/issuer records must actually be present
        # and current. This call creates no receipt and grants no self-approval.
        self.binding,self.release=consume_external_release(cfg=self.cfg,out=self.out,window=self.window,
            roles=self.roles,setup=ready,clock=self.clock,journal=self.journal,scope=self.scope)
        self.channel.send('RELEASE_BOUND',self.binding)
        self.ledger=ReleaseLedger(self.out/'release.custody.sqlite3')
        self.runtime=LinuxRuntimeObserver(self.supervisor)
        self.due=ControllerDueEvents(store=self.store,pending_changes=self.plans,binding=self.binding,
            clock=self.clock,current_state=lambda:self.current_state(),next_sequence=self.next_sequence)

    def guard_roles(self):
        from role_boundary import identity
        need(self.child is not None and self.child.poll() is None,'decision role exited')
        self.window.require_remaining(0)
        for role,expected in self.roles.items():
            actual=identity(expected['pid'])
            need(actual['start_ticks']==expected['start_ticks'] and actual['parent_pid']==expected['parent_pid'],
                 'released role process or parent changed')
            status=Path('/proc',str(expected['pid']),'status').read_text().splitlines()
            ids={line.split(':',1)[0]:line.split(':',1)[1].split() for line in status if line.startswith(('Uid:','Gid:'))}
            need(len(ids.get('Uid',[]))==4 and len(ids.get('Gid',[]))==4
                 and all(int(v)==expected['uid'] for v in ids['Uid'])
                 and all(int(v)==expected['gid'] for v in ids['Gid']),'released role credentials changed')
            for name,ns in expected['namespaces'].items():
                need(os.readlink('/proc/'+str(expected['pid'])+'/ns/'+name)==ns,'released role namespace changed')
            need(sha256(Path('/proc',str(expected['pid']),'mountinfo').read_bytes()).hexdigest()==expected['mountinfo_sha256'],
                 'released role mounts changed')
            need(os.readlink('/proc/'+str(expected['pid'])+'/exe')==expected['exe'],'released role executable changed')
        need(self.clock()<datetime.fromisoformat(self.binding['expires_at_utc'].replace('Z','+00:00')),'release expired')

    def prepare_source_binding(self, request, binding, observed, current_state):
        self.source_binding={'request_sha256':content_digest(request),
            'current_policy_binding_sha256':content_digest({'scope':binding['scope'],'policy_sha256':binding['policy_sha256'],'policy_revision':binding['policy_revision']}),
            'current_context_binding_sha256':content_digest({'context_sha256':binding['context_sha256'],'context_version':binding['context_version']}),
            'current_venue_readback_sha256':content_digest(observed),
            'current_evidence_bundle_sha256':content_digest(request.evidence)}
        self.current_state=current_state

    def adapter_backend(self, phase, gate):
        self.gates[phase]=gate
        def deny(_):raise RuntimeError('controller verifier cannot issue model HTTP')
        from model_guest_boundary import PHASES
        schema_rel=self.cfg.get('selection_schema_path','docs/contracts/decision-selection.schema.json')
        schema_bytes=(Path(self.cfg['source_directory'])/schema_rel).read_bytes()
        ports=ObservedModelPorts(store=self.store,phase=phase,runtime=self.runtime,clock=self.clock,execution_gate=deny)
        ports.backend(pin=self.pin,selection_schema_bytes=schema_bytes,
                      max_calls=PHASES[phase][0],max_total_seconds=PHASES[phase][4])
        exec_ports=_ControllerObservedPorts(
            owner=self,store=self._observer_store,phase=phase,runtime=self.runtime,
            clock=self.clock,execution_gate=gate,
        )
        self.executors[phase]=exec_ports.backend(
            pin=self.pin,selection_schema_bytes=schema_bytes,
            max_calls=PHASES[phase][0],max_total_seconds=PHASES[phase][4],
        )
        self.verifiers[phase]=ports
        self.readers[phase]=ModelDecisionReader(self.store,ports,expected_adapter_id='ollama-'+phase,require_transport=True)
        return ControllerBackend(self,phase),ports

    def _retire_previous_runner(self):
        if self._previous_runner is None:
            return
        expiry = min(self._invocation_deadline, self.clock() + timedelta(seconds=10))
        while _runner_alive(self._previous_runner['pid']) and self.clock() < expiry:
            time.sleep(0.05)
        need(not _runner_alive(self._previous_runner['pid']), 'previous model runner not unloaded')
        reap_expiry = min(self._invocation_deadline, self.clock() + timedelta(seconds=2))
        ollama_pid = getattr(self.runtime, 'ollama_pid', self.runtime.spec.ollama_pid)
        while _runner_in_children(ollama_pid, self._previous_runner['pid'], self.runtime.proc_root) and self.clock() < reap_expiry:
            time.sleep(0.02)

    def _handle(self, method, value):
        self.guard_roles();inv=self.active;need(inv is not None,'no current invocation')
        key=content_digest(inv)
        allowed=lambda row: row['receipt_id'].endswith('-'+key) and not row['kind'].startswith('MODEL_CONTROLLER_')
        if method=='GATE':
            need(value=={'invocation_sha256':key},'gate invocation differs');self.gates[self.phase](inv);return True
        if method=='STORE_RECORDS':
            need(value=={},'record query cannot select another scope');return [r for r in self.store.records() if allowed(r)]
        if method=='STORE_RESOLVE':
            need(set(value)=={'receipt_id'},'unknown resolve field');row=self.store.resolve(value['receipt_id'])
            need(allowed(row),'runner cannot resolve another request or controller record');return row
        if method=='STORE_CHECKPOINT':
            need(value=={},'unknown checkpoint query');return self.store.checkpoint()
        if method in ('STORE_BEGIN', 'STORE_APPEND', 'GENERATION_SUBMITTED', 'DUE_EVENT', 'VERIFY_TRANSPORT'):
            need(False, 'worker cannot author model/runtime/transport observation evidence or completed-send proofs')
        if method=='OBSERVED_PREFLIGHT':
            need(value=={'invocation_sha256':key} and self._preflight_done_key!=key,'exact one-shot controller preflight required')
            self._retire_previous_runner()
            counted=self.executors[self.phase].count_input_tokens(inv)
            self._preflight_done_key=key
            return {'input_tokens':int(counted)}
        if method=='OBSERVED_GENERATE':
            need(value=={'invocation_sha256':key} and self._preflight_done_key==key and self._generate_allowed_key==key,
                 'explicit controller-authorized generation required')
            self._generate_allowed_key=None
            reply=self.executors[self.phase].infer(inv)
            self._previous_runner=self.store.resolve('token-proof-'+key)['payload']['runtime']['runner']
            return {
                'receipt_id':reply.receipt_id,
                'raw_selection_json':reply.raw_selection_json,
                'input_tokens':int(reply.input_tokens),
                'generated_tokens':int(reply.generated_tokens),
            }
        if method=='OUTCOME':return self.outcome(value)
        raise RuntimeError('unknown runner operation')

    def exchange_until(self, expected):
        try:
            while True:
                self.guard_roles();method,value=self.channel.receive()
                if method in expected:return method,value
                try:self.channel.reply(self._handle(method,value))
                except Exception:
                    try:self.channel.send('RETURN',{'ok':False,'value':None})
                    except Exception as exc:_logger.debug('Failed to deliver RETURN error frame: %s',exc)  # preserve original failure
                    raise
        except Exception:
            # A missing response still has a durable original attempt outcome.
            key=content_digest(self.active)
            if not any(r['receipt_id']=='controller-outcome-'+key for r in self.store.records()):
                self.outcome({'invocation_sha256':key,'status':'UNKNOWN','receipt_id':None})
            raise

    def outcome(self, value):
        key=content_digest(self.active)
        need(set(value)=={'invocation_sha256','status','receipt_id'} and value['invocation_sha256']==key
             and value['status'] in ('COMPLETE','FAILED','UNKNOWN'),'invalid retained attempt outcome')
        records={r['receipt_id']:r for r in self.store.records()}
        response=records.get('generation-http-'+key);capture=records.get('generation-capture-'+key)
        inference=records.get('inference-'+key);selection=None;state_hash=None;window_hash=None
        status=value['status']
        if status=='COMPLETE':
            need(inference and value['receipt_id']==inference['receipt_id'] and response and capture,'completed source missing')
            if getattr(self.store, 'has_observer_key', False) and callable(getattr(self.store, 'require_observer_provenance', None)):
                for _pfx in REQUIRED_OBSERVER_RECEIPT_PREFIXES:
                    self.store.require_observer_provenance(_pfx + key)
            p=inference['payload']
            reply=decode(canonical_bytes(dict(raw_selection_json=p['raw_selection_json'],receipt_id=inference['receipt_id'],
                invocation_sha256=key,model=p['requested_model'],started_at=p['started_at'],completed_at=p['completed_at'],
                input_tokens=p['observed_provider_input_tokens'],generated_tokens=p['observed_provider_generated_tokens'])).decode(),InferenceReply)
            need(self.verifiers[self.phase].verify(reply,self.active) is True,'independent inference verification failed')
            selection=json.loads(reply.raw_selection_json)
            state_hash=content_digest(self.current_state())
            transport=verify_generation_transport(self.store,key)
            if self.due.active:
                proof={'verified':pending_ordering(self.due.active.observations,transport),'transport':transport}
                rec=self.store.append('controller-window-'+key,'MODEL_CONTROLLER_WINDOW_COMPLETION',proof,now=self.clock())
                window_hash=rec['sha256']
            self.reply=reply
        outcome=self.store.append('controller-outcome-'+key,'MODEL_CONTROLLER_ATTEMPT_OUTCOME',
            {'invocation_sha256':key,'status':status,'reported':value,'response_id':response['receipt_id'] if response else None,
             'capture_id':capture['receipt_id'] if capture else None,'current_state_sha256':state_hash},now=self.clock())
        payload={'generation_attempt_id':'generation-attempt-'+key,'generation_http_id':'generation-http-'+key,
            'invocation_sha256':key,'result_status':status,'selection':selection,
            'attempt_outcome_receipt_sha256':outcome['sha256'],
            'raw_response_receipt_sha256':response['sha256'] if response else None,
            'transport_capture_receipt_sha256':capture['sha256'] if capture else None,
            'token_usage_receipt_sha256':inference['sha256'] if inference and status=='COMPLETE' else None,
            'pending_window_completion_receipt_sha256':window_hash,'current_state_readback_sha256':state_hash}
        result=envelope('DECISION_RESULT',payload,binding=self.binding,
            request_id=json.loads(self.active.packet_json)['request_id'],sequence=self.next_sequence(),now=self.clock())
        self.ledger.acknowledge(self.delivery_id,result)
        self.expected_result=result
        return result

    def close(self):
        from approved_model_driver import stop_group
        try:
            if self.child is not None:
                try:
                    if self.child.poll() is None and self.channel is not None and not self.channel.closed:
                        self.channel.send('SHUTDOWN',{},deadline=self.clock()+timedelta(seconds=.25))
                except Exception as exc:_logger.debug('Best-effort child shutdown send skipped: %s',exc)
                stop_group(self.child)  # fixed bounded waits; no channel acknowledgement
        finally:
            try:
                if hasattr(self,'supervisor'):
                    import signal
                    from role_boundary import identity
                    try:
                        owned=identity(self.supervisor.ollama_pid)
                        if owned['start_ticks']==self.supervisor.ollama_start_ticks:
                            os.killpg(self.supervisor.ollama_pid,signal.SIGKILL)
                    except (FileNotFoundError,ProcessLookupError):pass
            finally:
                if self.channel is not None:self.channel.close()


class ControllerBackend:
    def __init__(self,owner,phase):self.owner,self.phase=owner,phase

    def count_input_tokens(self, invocation):
        o=self.owner;o.guard_roles();o.gates[self.phase](invocation)
        need(all(o.file_identity(path)==expected for path,expected in o.asset_identity.items()),
             'frozen source/runtime/model file identity changed before delivery')
        spent=[r for r in o.store.records() if r['kind']=='MODEL_HTTP_ATTEMPT' and r['payload']['operation']=='generation']
        probes=sum(r['payload']['phase']=='probe' for r in spent)
        acceptance=sum(r['payload']['phase']=='acceptance' for r in spent)
        need(probes<=2 and acceptance<=30,'fixed generation allocation exceeded')
        o.window.require_remaining((2-probes)*60+(30-acceptance)*120+60)
        need(invocation.request_sha256 not in o.spent_requests,'current frame already exposed; no redelivery')
        need(o.source_binding and o.source_binding['request_sha256']==invocation.request_sha256,'independent current source binding missing')
        o.spent_requests.add(invocation.request_sha256)
        o.active=invocation;o.phase=self.phase;o.frame_started=o.clock();o.reply=None
        invocation_deadline=min(o.window.end,
            datetime.fromisoformat(o.binding['expires_at_utc'].replace('Z','+00:00')),
            o.frame_started+timedelta(seconds=invocation.budget.max_seconds_per_call))
        o._invocation_deadline=invocation_deadline
        o._preflight_done_key=None;o._generate_allowed_key=None
        o.delivery_id='delivery-'+content_digest(invocation)
        o.channel.begin_invocation(o.delivery_id,invocation_deadline)
        o.due.begin(invocation,body=o.verifiers[self.phase]._backend._request(invocation).body)
        packet=json.loads(invocation.packet_json)
        payload={'delivery_id':o.delivery_id,'opportunity_set_id':packet['opportunity_set_id'],
            'current_packet':packet,'current_packet_sha256':content_digest(packet),
            'source_state_reference_sha256':content_digest(packet['state']),
            **{k:v for k,v in o.source_binding.items() if k!='request_sha256'}}
        frame_binding={**o.binding,'expires_at_utc':invocation_deadline.isoformat().replace('+00:00','Z')}
        frame=envelope('CURRENT_FRAME',payload,binding=frame_binding,request_id=packet['request_id'],
            sequence=o.next_sequence(),now=o.clock())
        need(o.ledger.expose(o.delivery_id,frame) is None,'retained acknowledgement cannot redeliver a frame')
        o.journal.append(o.delivery_id,'CURRENT_FRAME_EXPOSURE_INTENT',o.scope,
            {'frame_sha256':content_digest(frame),'request_sha256':invocation.request_sha256},now=o.clock())
        o.channel.send('CURRENT_FRAME',frame)
        method,value=o.exchange_until({'PREFLIGHT_READY','DECISION_RESULT'})
        need(method=='PREFLIGHT_READY' and set(value)=={'invocation_sha256','input_tokens'}
             and value['invocation_sha256']==content_digest(invocation),'current preflight failed or unknown')
        proof=o.store.resolve('token-proof-'+content_digest(invocation))
        need(type(value['input_tokens']) is int and value['input_tokens']==proof['payload']['input_tokens'], 'preflight count differs')
        return value['input_tokens']

    def infer(self, invocation):
        o=self.owner;need(o.active==invocation,'generation differs from current preflight')
        o._generate_allowed_key=content_digest(invocation)
        o.channel.send('GENERATE',{'invocation_sha256':content_digest(invocation)})
        _,value=o.exchange_until({'DECISION_RESULT'})
        validate_message(value,binding=o.binding,now=o.clock())
        need(value==o.expected_result and value['payload']['result_status']=='COMPLETE'
             and o.reply is not None,'failed/unknown result is not WAIT')
        o.channel.finish_invocation(o.delivery_id)
        return o.reply
