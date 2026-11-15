"""Eight concrete public receiver challenges. No fixtures become success labels."""
from __future__ import annotations
import array
import hashlib
import hmac
import os
import select
import signal
import socket
import struct
import time
from cas_forex_operational_contracts.common import canonical_bytes,decode_canonical,require,ContractError
from .capture import CaptureSession
from .inventory import require_owned_child_lifecycle,terminate_owned_child
from .receiver_capture import MeasuredSender,own_descriptor

KINDS=('POSITIVE_INERT','BAD_MAC','BAD_SEQUENCE','BAD_CHANNEL_ID','BAD_FRAME',
       'DELIVERED_RIGHTS','TRUNCATED_RIGHTS','WRONG_PEER_PID')
EXPECTED={'POSITIVE_INERT':('ACCEPTED_INERT','NONE'),'BAD_MAC':('AUTH_REJECTED','MAC'),
 'BAD_SEQUENCE':('AUTH_REJECTED','SEQUENCE'),'BAD_CHANNEL_ID':('AUTH_REJECTED','CHANNEL_ID'),
 'BAD_FRAME':('FRAMING_REJECTED','FRAME'),'DELIVERED_RIGHTS':('RIGHTS_REJECTED','ANCILLARY'),
 'TRUNCATED_RIGHTS':('FRAMING_REJECTED','ANCILLARY'),'WRONG_PEER_PID':('AUTH_REJECTED','PEER_CREDENTIALS')}


def public_fixture_key(fixture_raw, key_id):
    """Public deterministic material; never use for a final/private channel."""
    fixture=decode_canonical(fixture_raw)
    require(set(fixture)=={'case_kind','public_only'} and fixture['case_kind'] in KINDS and fixture['public_only'] is True,'PUBLIC_FIXTURE')
    require(type(key_id) is str and key_id,'PUBLIC_KEY_ID')
    return hashlib.sha256(b'CAS_FOREX_PUBLIC_CALIBRATION_V1\n'+fixture_raw+b'\n'+key_id.encode('utf-8')).digest()


def public_packet(*,key,channel_id,value,kind):
    require(kind in KINDS,'CALIBRATION_KIND')
    body={'channel_id':channel_id+'-different' if kind=='BAD_CHANNEL_ID' else channel_id,
          'sequence':1,'method':'PUBLIC_INERT','value':value}
    mac=hmac.new(key,canonical_bytes(body),hashlib.sha256).hexdigest()
    if kind=='BAD_MAC':mac=('0' if mac[0]!='0' else '1')+mac[1:]
    app=canonical_bytes({'body':body,'mac':mac})
    require(len(app)<=32768,'PUBLIC_FIXTURE_TOO_LARGE')
    frame=struct.pack('!II',len(app),1 if kind=='BAD_FRAME' else 0)+app
    return app,frame


class ForkedMeasuredSender:
    """Prepared actual foreign PID, selected before CALIBRATION_BEGIN.

    prepare() forks only public fixture material, waits for the child's own
    SIGSTOP, and exposes an actual stable subject for authenticated selection.
    send_prepared() later resumes that same child. No post-selection replacement.
    """
    def __init__(self,*,inventory,session,execution_gate):
        self.inventory,self.session,self.gate=inventory,session,execution_gate
        self.pid=None;self.pidfd=None;self.ack=None;self.report=None;self.subject=None;self.batch=None
        self.blob_manifest_refs=();self.exchange=None;self.sent=False;self.retired=False
    def prepare(self,connection,application,frame,*,exchange_id,target_id):
        require(self.pid is None and self.gate() is None,'CHALLENGER_ONE_SHOT')
        require(type(application) is bytes and type(frame) is bytes and len(frame)<=32776,'PUBLIC_CHALLENGER_BYTES')
        packet=decode_canonical(application);value=packet.get('body',{}).get('value')
        require(type(value) is dict and set(value)=={'case_kind','public_only'} and value['case_kind']=='WRONG_PEER_PID'
            and value['public_only'] is True and packet['body']['method']=='PUBLIC_INERT','CHALLENGER_PUBLIC_ONLY')
        require_owned_child_lifecycle()
        start=self.session.guard.now();out_read,out_write=os.pipe2(os.O_CLOEXEC);ack_read,ack_write=os.pipe2(os.O_CLOEXEC)
        pid=os.fork()
        if pid==0:
            try:
                keep={0,1,2,connection.fileno(),out_write,ack_read}
                for fd in [int(x) for x in os.listdir('/proc/self/fd')]:
                    if fd not in keep:
                        try:os.close(fd)
                        except OSError:pass
                os.kill(os.getpid(),signal.SIGSTOP)
                subject=self.inventory.subject(os.getpid(),'TEMPORARY_CHALLENGER')
                child=CaptureSession(budget=self.session.budget,producer_id=self.session.meta['producer_id'],origin='CONTROLLER',
                    evidence_class='PUBLIC_RECEIVER_OBSERVATION',subject=subject,guard=self.session.guard,sink=self.session.sink,
                    capture_id='challenger-'+exchange_id,receiver_component_sha256=self.session.meta['receiver_component_sha256'])
                self.inventory.boundary(os.getpid(),role='TEMPORARY_CHALLENGER',session=child)
                MeasuredSender(connection,session=child,inventory=self.inventory,role='TEMPORARY_CHALLENGER',target_id=target_id).send(frame,application,exchange_id=exchange_id)
                batch=child.seal()
                # This bounded child-to-controller transport is not an authority
                # record. Both existing bodies still need external attestation.
                raw=canonical_bytes({'batch':batch,'blob_manifest_refs':list(child.blob_manifests)})
                view=memoryview(struct.pack('!I',len(raw))+raw)
                while view:
                    n=os.write(out_write,view);require(n>0,'CHALLENGER_REPORT');view=view[n:]
                os.close(out_write)
                ready,_,_=select.select([ack_read],[],[],self.session.guard.remaining())
                require(ready and os.read(ack_read,1)==b'R','CHALLENGER_RETIREMENT')
                connection.close();os.close(ack_read);os._exit(0)
            except BaseException:os._exit(125)
        os.close(out_write);os.close(ack_read);self.pid=pid;self.ack=ack_write;self.report=out_read;self.exchange=exchange_id
        try:
            self.pidfd=os.pidfd_open(pid)
            while True:
                self.session.guard.now();got,status=os.waitpid(pid,os.WNOHANG|os.WUNTRACED)
                if got:require(os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGSTOP,'CHALLENGER_NOT_PAUSED');break
                time.sleep(min(0.005,self.session.guard.remaining()))
            self.subject=self.inventory.subject(pid,'TEMPORARY_CHALLENGER')
            self.inventory.boundary(pid,role='TEMPORARY_CHALLENGER',session=self.session)
            return dict(self.subject)
        except BaseException:self.abort();raise
    def send_prepared(self,*,exchange_id):
        require(self.subject is not None and not self.sent and exchange_id==self.exchange,'CHALLENGER_NOT_PREPARED')
        require(self.inventory.subject(self.pid,'TEMPORARY_CHALLENGER')==self.subject,'CHALLENGER_CHANGED')
        self.session.guard.now();self.sent=True;signal.pidfd_send_signal(self.pidfd,signal.SIGCONT)
        try:
            data=bytearray();size=None
            while size is None or len(data)<size+4:
                ready,_,_=select.select([self.report],[],[],self.session.guard.remaining())
                require(ready,'CHALLENGER_REPORT_TIMEOUT');block=os.read(self.report,65536)
                require(block,'CHALLENGER_REPORT_TRUNCATED');data.extend(block)
                if size is None and len(data)>=4:size=struct.unpack('!I',data[:4])[0];require(0<size<=1_048_576,'CHALLENGER_REPORT_BOUND')
                require(len(data)<=1_048_580,'CHALLENGER_REPORT_BOUND')
            require(len(data)==size+4,'CHALLENGER_REPORT_TRAILING')
            from cas_forex_operational_contracts import capture as c,method as m
            body=decode_canonical(bytes(data[4:]));require(set(body)=={'batch','blob_manifest_refs'},'CHALLENGER_REPORT_SHAPE')
            batch=c.validate('CaptureBatch',body['batch']).payload()
            require(batch['subject']==self.subject and self.inventory.subject(self.pid,'TEMPORARY_CHALLENGER')==self.subject
                and batch['binding']==self.session.budget['binding'],'CHALLENGER_IDENTITY')
            require(len(body['blob_manifest_refs'])<=256,'CHALLENGER_MANIFEST_COUNT')
            for ref in body['blob_manifest_refs']:
                m.validate('ObjectRef',ref);require(ref['artifact_kind']=='RAW_BLOB_MANIFEST','CHALLENGER_MANIFEST_KIND');self.session.sink.readback(ref)
            self.batch=batch;self.blob_manifest_refs=tuple(body['blob_manifest_refs'])
            return batch
        except BaseException:self.abort();raise
        finally:
            if self.report is not None:os.close(self.report);self.report=None
    def retire(self):
        require(self.pid is not None and self.subject is not None and not self.retired,'CHALLENGER_UNAVAILABLE')
        start=self.session.guard.now()
        require(self.inventory.subject(self.pid,'TEMPORARY_CHALLENGER')==self.subject,'CHALLENGER_CHANGED')
        tasks=self.inventory.proc/str(self.pid)/'task';children=set()
        for task in tasks.iterdir():children.update((task/'children').read_text().split())
        require(not children,'UNKNOWN_CHALLENGER_DESCENDANTS')
        os.write(self.ack,b'R');os.close(self.ack);self.ack=None
        while True:
            self.session.guard.now();pid,status=os.waitpid(self.pid,os.WNOHANG)
            if pid:break
            time.sleep(min(0.005,self.session.guard.remaining()))
        require(os.WIFEXITED(status) and os.WEXITSTATUS(status)==0,'CHALLENGER_RETIREMENT_FAILED')
        self.retired=True;os.close(self.pidfd);self.pidfd=None
        return self.session.add('CHILD_RETIREMENT',{'subject':self.subject,'known_descendants':[],
            'wait_result':'EXITED','wait_status':status,'remaining_live_subjects':[],
            'endpoint_close_refs':[],'delivered_close_refs':[]},started=start)
    def abort(self):
        if self.pid is not None and not self.retired:terminate_owned_child(self.pid,self.pidfd)
        if self.pidfd is not None:os.close(self.pidfd);self.pidfd=None
        for name in ('ack','report'):
            value=getattr(self,name)
            if value is not None:
                try:os.close(value)
                except OSError:pass
                setattr(self,name,None)
        # No retirement receipt: timeout/error cleanup remains unavailable.


class CalibrationRunner:
    def __init__(self,*,session,inventory,receiver_factory,execution_gate,foreign_sender=None):
        require(callable(receiver_factory) and callable(execution_gate),'CALIBRATION_DEPENDENCY')
        self.session,self.inventory,self.factory,self.gate=session,inventory,receiver_factory,execution_gate
        self.foreign_sender=foreign_sender
        self.attempted=set()
        self.completed=[];self.channels=set();self.instances=set();self.keys=set();self.foreign_batches=[]
    def exercise(self,expectation,*,public_value,public_key,public_key_id,rights_fd=None):
        fixture_raw=self.session.sink.readback(expectation['fixture_ref'])
        require(public_key==public_fixture_key(fixture_raw,public_key_id),'PUBLIC_KEY_RECIPE')
        require(public_value==decode_canonical(fixture_raw),'CALIBRATION_PUBLIC_VALUE')
        kind=expectation['case_kind'];require(kind in KINDS and kind not in self.attempted,'CALIBRATION_DUPLICATE')
        require(self.gate() is None,'RUNTIME_APPROVAL_ABSENT')
        self.attempted.add(kind)
        receiver,sender=self.factory(expectation,public_key,public_key_id)
        foreign=self.foreign_sender if kind=='WRONG_PEER_PID' else None;results=[]
        try:
            require(receiver.component==expectation['receiver_component_sha256'] and receiver.sequence==0 and not receiver.closed,'CALIBRATION_INSTANCE')
            require(receiver.channel not in self.channels and receiver.instance not in self.instances and public_key_id not in self.keys,'CALIBRATION_REUSED_INSTANCE')
            self.channels.add(receiver.channel);self.instances.add(receiver.instance);self.keys.add(public_key_id)
            receiver.prepare();application,frame=public_packet(key=public_key,channel_id=receiver.channel,value=public_value,kind=kind)
            for index in range(2 if kind=='BAD_SEQUENCE' else 1):
                exchange=expectation['case_id']+'-exchange-'+str(index+1);ancillary=[]
                begin=len(self.session.operations)
                if kind in ('DELIVERED_RIGHTS','TRUNCATED_RIGHTS'):
                    require(type(rights_fd) is int and rights_fd>=0,'PUBLIC_RIGHT_REQUIRED');os.fstat(rights_fd)
                    ancillary=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[rights_fd]*(252 if kind=='TRUNCATED_RIGHTS' else 1)).tobytes())]
                if kind=='WRONG_PEER_PID':
                    foreign=self.foreign_sender
                    require(foreign is not None and foreign.subject is not None,'PRESELECTED_FOREIGN_SENDER_REQUIRED')
                    self.foreign_batches.append(foreign.send_prepared(exchange_id=exchange))
                else:sender.send(frame,application,exchange_id=exchange,ancillary=ancillary)
                result=receiver.receive_inert(exchange_id=exchange)
                observed=[x for x in self.session.operations[begin:] if x['kind']=='RECV']
                require(len(observed)==1,'CALIBRATION_RECEIVE_COUNT');recv=observed[0]['data']
                rights=recv['delivered_descriptors'];flags=recv['msg_flags']
                require(not flags&socket.MSG_TRUNC,'CALIBRATION_DATA_TRUNCATED')
                require(bool(flags&socket.MSG_CTRUNC)==(kind=='TRUNCATED_RIGHTS'),'CALIBRATION_CTRUNC_MISMATCH')
                require(bool(rights)==(kind in ('DELIVERED_RIGHTS','TRUNCATED_RIGHTS')),'CALIBRATION_RIGHTS_MISMATCH')
                if kind=='WRONG_PEER_PID':
                    require(recv['ucred']=={'pid':foreign.pid,'uid':foreign.subject['uid'],'gid':foreign.subject['gid']}
                        and foreign.pid!=receiver.peer['pid'] and (foreign.subject['uid'],foreign.subject['gid'])==(receiver.peer['uid'],receiver.peer['gid']),'CALIBRATION_FOREIGN_IDENTITY')
                elif kind!='TRUNCATED_RIGHTS':require(recv['ucred']=={k:receiver.peer[k] for k in ('pid','uid','gid')},'CALIBRATION_CREDENTIALS')
                expected=('ACCEPTED_INERT','NONE') if kind=='BAD_SEQUENCE' and index==0 else EXPECTED[kind]
                require((result['verdict'],result['rejection_stage'])==expected,'CALIBRATION_UNEXPECTED_OUTCOME')
                results.append(result)
        finally:
            # Attempt every cleanup independently, even after an earlier failure.
            cleanup_failed=False
            try:receiver.close()
            except BaseException:cleanup_failed=True
            identity=None;stamp=self.session.guard.clock.stamp();ret=-1;error=0
            try:identity=own_descriptor(sender.socket.fileno(),sender.target)
            except OSError:cleanup_failed=True
            try:sender.socket.close();ret=0
            except OSError as exc:error=exc.errno or 0;cleanup_failed=True
            if identity is not None:
                try:self.session.add('CLOSE',{'exchange_id':None,'descriptor':identity,'return_value':ret,'errno':error},started=stamp,finished=self.session.guard.clock.stamp())
                except BaseException:cleanup_failed=True
            if foreign is not None and foreign.subject is not None:
                try:foreign.retire()
                except BaseException:foreign.abort();cleanup_failed=True
            require(not cleanup_failed,'CALIBRATION_CLEANUP_UNCONFIRMED')
        self.session.guard.now()
        self.completed.append(kind)
        return tuple(results)
    def require_complete(self):
        require(set(self.completed)==set(KINDS) and len(self.completed)==8,'CALIBRATION_INCOMPLETE')
        return tuple(self.completed)
