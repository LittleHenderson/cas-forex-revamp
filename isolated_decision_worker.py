"""Explicit clean decision role. Receives current packets, never custody files."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import time

from role_boundary import confine, identity, need, open_probe


def read_boot(fd):
    with os.fdopen(fd,'rb') as handle: raw=handle.read(4194305)
    need(0<len(raw)<=4194304,'bounded role bootstrap required')
    return json.loads(raw)


def stop(child):
    import signal
    for sig in (signal.SIGTERM,signal.SIGKILL):
        try: os.killpg(child.pid,sig)
        except ProcessLookupError: pass
        if sig==signal.SIGTERM:
            try: child.wait(timeout=1)
            except subprocess.TimeoutExpired: pass
    child.wait(timeout=1)


def _runner_alive(pid):
    try: txt=Path('/proc',str(pid),'stat').read_text()
    except FileNotFoundError: return False
    return txt[txt.rfind(')')+2:].split()[0]!='Z'


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--bootstrap-fd',type=int,required=True)
    parser.add_argument('--channel-fd',type=int,required=True);args=parser.parse_args()
    cfg=read_boot(args.bootstrap_fd)
    parent=identity(os.getppid());need(parent==cfg['parent'],'bootstrap parent changed')
    observed=confine(cfg['policy'],allowed_fds={args.channel_fd},boot_id=cfg['boot_id'])
    probes=[open_probe(p) for p in cfg['probe_paths']]
    sys.path.insert(0,str(Path(cfg['source_directory'])/'src'))
    from cas_forex_revamp.contracts import InferenceBudget, canonical_bytes, content_digest
    from cas_forex_revamp.core.storage import decode
    from cas_forex_revamp.operator.model import ModelInvocation, ModelSpecification, SYSTEM_POLICY
    from cas_forex_revamp.operator.ollama_backend import OllamaRuntimePin
    from cas_forex_revamp.operator.runtime_observer import LinuxRuntimeObserver, PinnedFile, SupervisorSpec
    from cas_forex_revamp.operator.token_preflight import tokenizer_identity
    from cas_forex_revamp.composition.custody_protocol import validate_message
    from cas_forex_revamp.composition.role_channel import RoleChannel
    from cas_forex_revamp.composition.remote_model_ports import CurrentModelStore, RemoteObservedPorts
    from model_guest_boundary import PHASES
    clock=lambda:datetime.now(timezone.utc)
    deadline=datetime.fromisoformat(cfg['deadline'])
    channel=RoleChannel(socket.socket(fileno=args.channel_fd),key=bytes.fromhex(cfg.pop('channel_key')),
        channel_id=cfg['channel_id'],peer_pid=parent['pid'],peer_start_ticks=parent['start_ticks'],deadline=deadline)
    child=None
    try:
        model_cfg=cfg['model_bootstrap']; r,w=os.pipe(); ready_r,ready_w=os.pipe()
        try:
            child=subprocess.Popen(['/usr/bin/python3','-B',str(Path(cfg['source_directory'])/'isolated_model_exec.py'),
                '--bootstrap-fd',str(r),'--ready-fd',str(ready_w)],cwd=model_cfg['cwd'],env=cfg['clean_environment'],
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                pass_fds=(r,ready_w),close_fds=True,start_new_session=True)
        finally: os.close(r);os.close(ready_w)
        with os.fdopen(w,'wb') as handle:handle.write(canonical_bytes(model_cfg))
        try:
            need(select.select([ready_r],[],[],10)[0],'model confinement observation unavailable')
            chunks=bytearray()
            while True:
                need(select.select([ready_r],[],[],5)[0],'model observation timed out')
                block=os.read(ready_r,65536)
                if not block:break
                chunks.extend(block);need(len(chunks)<=65536,'model observation too large')
            model_boundary=json.loads(chunks)
        finally:os.close(ready_r)
        child_identity=identity(child.pid)
        need(child_identity['parent_pid']==os.getpid(),'model is not owned direct child')
        files=tuple(PinnedFile(**x) for x in cfg['role_files'])
        supervisor=SupervisorSpec(child.pid,child_identity['start_ticks'],files)
        runtime=LinuxRuntimeObserver(supervisor)
        until=min(deadline,clock()+timedelta(seconds=180))
        while True:
            need(child.poll() is None and clock()<until,'model startup failed')
            try: prepared=runtime.prepare();break
            except (FileNotFoundError,ValueError):time.sleep(0.1)
        pin_source=json.loads((Path(cfg['source_directory'])/'docs/operator/stage-b-runtime-pin.json').read_bytes())
        schema=(Path(cfg['source_directory'])/cfg.get('selection_schema_path','docs/contracts/decision-selection.schema.json')).read_bytes()
        role_files={x.role:x for x in files}
        model=ModelSpecification('qwen3:0.6b',role_files['weight'].sha256,'disabled',cfg['prompt_version'])
        pin=OllamaRuntimePin('0.40.2',pin_source['runtime']['publisher_sha256'],model,
            role_files['manifest'].sha256,role_files['template'].sha256,tokenizer_identity(prepared['files']),
            __import__('hashlib').sha256(schema).hexdigest())
        channel.send('ROLE_READY',{'runner':observed,'runner_probes':probes,'model':model_boundary,
            'supervisor':json.loads(canonical_bytes(supervisor)),'pin':json.loads(canonical_bytes(pin))})
        method,binding=channel.receive();need(method=='RELEASE_BOUND','release required before current frames')
        channel.custody_binding=binding
        store=CurrentModelStore(channel,run_id=cfg['run_id'],deadline=deadline)
        active=None
        def gate(invocation):
            need(active is not None and invocation==active and clock()<deadline,'exact current invocation/window required')
            channel.call('GATE',{'invocation_sha256':content_digest(invocation)})
        ports={};backends={};counts={'probe':0,'acceptance':0}
        for phase in ('probe','acceptance'):
            p=RemoteObservedPorts(channel=channel,store=store,phase=phase,runtime=runtime,clock=clock,execution_gate=gate)
            ports[phase]=p
            backends[phase]=p.backend(pin=pin,selection_schema_bytes=schema,max_calls=PHASES[phase][0],max_total_seconds=PHASES[phase][4])
        previous_runner=None
        while True:
            # Waiting for the next frame is bounded too; the authenticated frame
            # then supplies the earlier original controller-minted deadline.
            method, frame=channel.receive(deadline=clock()+timedelta(seconds=120))
            if method=='SHUTDOWN':need(frame=={},'unknown shutdown fields');break
            need(method=='CURRENT_FRAME','current frame required')
            channel.accept_public(frame,binding)
            need(frame['kind']=='CURRENT_FRAME','wrong direction')
            packet=frame['payload']['current_packet']
            phase='probe' if counts['probe']<2 else 'acceptance'
            need(counts[phase]<PHASES[phase][0],'phase exhausted')
            delivery_id=frame['payload']['delivery_id']
            invocation_deadline=datetime.fromisoformat(frame['expires_at_utc'].replace('Z','+00:00'))
            need(invocation_deadline<=datetime.fromisoformat(frame['not_before_utc'].replace('Z','+00:00'))
                 +timedelta(seconds=PHASES[phase][3]),'frame extends per-invocation budget')
            channel.begin_invocation(delivery_id,invocation_deadline)
            # No previous model context may carry into another trajectory. The
            # pinned keep_alive=0 route must actually retire the old runner.
            if previous_runner is not None:
                expiry=min(invocation_deadline,clock()+timedelta(seconds=10))
                while _runner_alive(previous_runner['pid']) and clock()<expiry:time.sleep(.05)
                need(not _runner_alive(previous_runner['pid']),'previous model runner not unloaded')
            active=ModelInvocation(packet['exact_request_sha256'],model,
                'session-'+content_digest((cfg['run_id']+'-'+phase,packet['request_id'],counts[phase])),
                SYSTEM_POLICY,canonical_bytes(packet).decode(),InferenceBudget(*PHASES[phase]),seed=cfg['seed'])
            key=content_digest(active)
            try:
                counted=backends[phase].count_input_tokens(active)
                channel.send('PREFLIGHT_READY',{'invocation_sha256':key,'input_tokens':counted})
                method,value=channel.receive()
                need(method=='GENERATE' and value=={'invocation_sha256':key},'explicit exact generation request required')
                counts[phase]+=1
                reply=backends[phase].infer(active)
                previous_runner=store.resolve('token-proof-'+key)['payload']['runtime']['runner']
                # The controller independently resolves raw receipts and builds
                # the public-contract proposal envelope from this exact outcome.
                result=channel.call('OUTCOME',{'invocation_sha256':key,'status':'COMPLETE','receipt_id':reply.receipt_id})
                channel.accept_public(result,binding)
                channel.send('DECISION_RESULT',result)
                channel.finish_invocation(delivery_id)
            except Exception as exc:
                # A failed/partial channel cannot report over a fresh wait. The
                # controller retains UNKNOWN independently when this role exits.
                if not channel.closed:
                    result=channel.call('OUTCOME',{'invocation_sha256':key,'status':'FAILED','receipt_id':None})
                    channel.accept_public(result,binding)
                    channel.send('DECISION_RESULT',result)
                break
            finally:active=None
    finally:
        channel.close()
        if child is not None:stop(child)


if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit(1)
