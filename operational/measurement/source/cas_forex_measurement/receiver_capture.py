"""Actual Unix packet I/O and verifier instrumentation; no application handler.

The selected integration receiver must use this implementation and repin its
component. Recorded gates come from these branches, never from caller labels.
"""
from __future__ import annotations
import array
import fcntl
import hashlib
import hmac
import os
import socket
import struct
from cas_forex_operational_contracts.common import canonical_bytes,decode_canonical,digest,require,ContractError
from .inventory import descriptor


def own_descriptor(fd,target):
    flags=fcntl.fcntl(fd,fcntl.F_GETFL)
    if fcntl.fcntl(fd,fcntl.F_GETFD)&fcntl.FD_CLOEXEC:flags|=os.O_CLOEXEC
    return descriptor(fd,os.fstat(fd),flags,target)


class MeasuredSender:
    def __init__(self,connection,*,session,inventory,role,target_id):
        self.socket,self.session,self.inventory,self.role,self.target=connection,session,inventory,role,target_id
    def send(self,frame,application,*,exchange_id,ancillary=()):
        start=self.session.guard.now();sender=self.inventory.subject(os.getpid(),self.role)
        frame_ref=self.session.raw(frame,selector='WIRE_FRAME',started=start,finished=start)
        app_ref=self.session.raw(application,selector='APPLICATION_PACKET',started=start,finished=start)
        require(frame_ref is not None and app_ref is not None,'EMPTY_SEND')
        refs=[]
        for level,kind,raw in ancillary:
            ref=self.session.raw(raw,selector='ANCILLARY_BYTES',started=start,finished=start)
            require(ref is not None,'EMPTY_ANCILLARY_CAPTURE')
            refs.append({'level':level,'type':kind,'raw_ref':ref})
        self.socket.settimeout(self.session.guard.remaining())
        try:result=self.socket.sendmsg([frame],list(ancillary));error=0
        except OSError as exc:result=-1;error=exc.errno or 0
        end=self.session.guard.clock.stamp()
        ref=self.session.add('SEND',{'exchange_id':exchange_id,'sender':sender,
            'socket_descriptor':own_descriptor(self.socket.fileno(),self.target),'frame_ref':frame_ref,
            'application_ref':app_ref,'ancillary_sent':refs,'return_value':result,'errno':error},started=start,finished=end)
        require(result==len(frame) and error==0,'SEND_FAILED_OR_PARTIAL');self.session.guard.now()
        return ref


class ObservedReceiver:
    MAX_MESSAGE=8_388_608
    FRAME_BYTES=32_776
    ANCILLARY_BYTES=64
    def __init__(self,connection,*,key,channel_id,expected_peer,component_sha256,instance_id,key_operation_id,
                 session,inventory,target_id):
        require(type(key) is bytes and len(key)==32,'RECEIVER_KEY_INPUT')
        self.socket,self.key,self.channel=connection,key,channel_id
        self.peer,self.component,self.instance,self.key_id=expected_peer,component_sha256,instance_id,key_operation_id
        self.session,self.inventory,self.target=session,inventory,target_id
        self.sequence=0;self.closed=False;self.prepared=False
    def prepare(self):
        self.session.guard.now();require(not self.prepared,'RECEIVER_ALREADY_PREPARED')
        self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);self.prepared=True
    def _gate(self,exchange,gate,outcome,refs,before):
        stamp=self.session.guard.clock.stamp()
        return self.session.add('VERIFIER_GATE',{'exchange_id':exchange,'receiver_component_sha256':self.component,
            'instance_id':self.instance,'channel_instance_id':self.channel,'key_operation_id':self.key_id,'gate':gate,
            'input_refs':refs,'outcome':outcome,'sequence_before':before,'sequence_after':self.sequence,
            'handler_entries_before':0,'handler_entries_after':0,'receiver_closed':self.closed},started=stamp,finished=stamp)
    def close(self,exchange_id=None):
        if self.closed:return
        identity=own_descriptor(self.socket.fileno(),self.target);stamp=self.session.guard.clock.stamp()
        self.closed=True;ret=-1;error=0
        try:self.socket.close();ret=0
        except OSError as exc:error=exc.errno or 0
        self.session.add('CLOSE',{'exchange_id':exchange_id,'descriptor':identity,'return_value':ret,'errno':error},started=stamp,finished=self.session.guard.clock.stamp())
        require(ret==0,'ENDPOINT_CLEANUP_UNCONFIRMED')
    def _finish(self,exchange,before,verdict,stage,refs,value=None):
        if verdict!='ACCEPTED_INERT':self.close(exchange)
        self._gate(exchange,'VERDICT',verdict,refs,before)
        self._gate(exchange,'EXPOSURE',verdict,refs,before)
        return {'verdict':verdict,'rejection_stage':stage,'value':value,'sequence':self.sequence,'closed':self.closed}
    def receive_inert(self,*,exchange_id):
        require(self.prepared and not self.closed,'RECEIVER_UNAVAILABLE')
        before=self.sequence;answer=bytearray();expected_size=None;refs=[]
        try:
            while expected_size is None or len(answer)<expected_size:
                start=self.session.guard.now();self.socket.settimeout(self.session.guard.remaining())
                identity=own_descriptor(self.socket.fileno(),self.target)
                receiver=self.inventory.subject(os.getpid(),'CONTROLLER')
                data,ancillary,flags,_=self.socket.recvmsg(self.FRAME_BYTES,self.ANCILLARY_BYTES)
                end=self.session.guard.clock.stamp()
                # Discover all delivered rights first. Always try each close, even if inspection/retention fails.
                rights=[];creds=[];other=False;malformed=False
                for level,kind,raw in ancillary:
                    if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                        parsed=array.array('i');n=len(raw)-len(raw)%parsed.itemsize
                        parsed.frombytes(raw[:n]);rights.extend(parsed.tolist());malformed|=n!=len(raw)
                    elif level==socket.SOL_SOCKET and kind==socket.SCM_CREDENTIALS:
                        if len(raw)==struct.calcsize('3i'):creds.append(struct.unpack('3i',raw))
                        else:malformed=True
                    else:other=True
                delivered=[];closes=[];incomplete=False;record_error=None
                try:
                    for fd in rights:
                        try:delivered.append(own_descriptor(fd,'delivered-right'))
                        except OSError:incomplete=True
                    raw_data=self.session.raw(data,selector='WIRE_FRAME',started=start,finished=end)
                    ancillary_bytes=canonical_bytes([{'level':l,'type':k,'hex':r.hex()} for l,k,r in ancillary])
                    raw_anc=self.session.raw(ancillary_bytes,selector='ANCILLARY_BYTES',started=start,finished=end,encoding='CANONICAL_JSON')
                    require(raw_data is not None,'EMPTY_RECEIVE')
                    cred={'pid':creds[0][0],'uid':creds[0][1],'gid':creds[0][2]} if len(creds)==1 else None
                    ref=self.session.add('RECV',{'exchange_id':exchange_id,'receiver':receiver,'socket_descriptor':identity,
                        'data_ref':raw_data,'ancillary_raw_ref':raw_anc,'msg_flags':flags,'return_value':len(data),'errno':0,
                        'ucred':cred,'delivered_descriptors':delivered},started=start,finished=end);refs.append(ref)
                except Exception as exc:record_error=exc
                finally:
                    known={x['fd']:x for x in delivered}
                    for fd in rights:
                        stamp=self.session.guard.clock.stamp();ret=-1;error=0
                        try:os.close(fd);ret=0
                        except OSError as exc:error=exc.errno or 0;incomplete=True
                        if fd not in known:incomplete=True;continue
                        try:
                            closes.append(self.session.add('CLOSE',{'exchange_id':exchange_id,'descriptor':known[fd],
                                'return_value':ret,'errno':error},started=stamp,finished=self.session.guard.clock.stamp()))
                        except Exception:incomplete=True
                if record_error is not None:raise ContractError('RAW_EVIDENCE_UNAVAILABLE') from None
                require(not incomplete,'DELIVERED_DESCRIPTOR_CLEANUP_UNCONFIRMED')
                self.session.guard.now()
                if flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC):
                    self._gate(exchange_id,'ANCILLARY','CHECK_FAIL',refs+closes,before)
                    return self._finish(exchange_id,before,'FRAMING_REJECTED','ANCILLARY',refs+closes)
                if rights or other or malformed or any(l==socket.SOL_SOCKET and k==socket.SCM_RIGHTS for l,k,_ in ancillary):
                    self._gate(exchange_id,'ANCILLARY','CHECK_FAIL',refs+closes,before)
                    return self._finish(exchange_id,before,'RIGHTS_REJECTED','ANCILLARY',refs+closes)
                self._gate(exchange_id,'ANCILLARY','CHECK_PASS',refs,before)
                actual=self.inventory.subject(self.peer['pid'],'CONTROLLER')
                live=(actual['boot_id'],actual['pid'],actual['start_ticks'],actual['uid'],actual['gid'])
                expected=tuple(self.peer[k] for k in ('boot_id','pid','start_ticks','uid','gid'))
                if len(creds)!=1 or creds[0]!=(self.peer['pid'],self.peer['uid'],self.peer['gid']) or live!=expected:
                    self._gate(exchange_id,'PEER_CREDENTIALS','CHECK_FAIL',refs,before)
                    return self._finish(exchange_id,before,'AUTH_REJECTED','PEER_CREDENTIALS',refs)
                self._gate(exchange_id,'PEER_CREDENTIALS','CHECK_PASS',refs,before)
                valid=len(data)>8
                if valid:
                    size,offset=struct.unpack('!II',data[:8])
                    valid=0<size<=self.MAX_MESSAGE and (expected_size is None or size==expected_size) and offset==len(answer) and len(answer)+len(data)-8<=size
                if not valid:
                    self._gate(exchange_id,'FRAME','CHECK_FAIL',refs,before)
                    return self._finish(exchange_id,before,'FRAMING_REJECTED','FRAME',refs)
                expected_size=size;answer.extend(data[8:]);self._gate(exchange_id,'FRAME','CHECK_PASS',refs,before)
            packet=decode_canonical(bytes(answer),limit=self.MAX_MESSAGE)
            require(type(packet) is dict and set(packet)=={'body','mac'},'CHANNEL_ENVELOPE')
            body=packet['body'];require(type(body) is dict and set(body)=={'channel_id','sequence','method','value'},'CHANNEL_BODY')
            expected_mac=hmac.new(self.key,canonical_bytes(body,limit=self.MAX_MESSAGE),hashlib.sha256).hexdigest()
            if type(packet['mac']) is not str or not hmac.compare_digest(packet['mac'],expected_mac):
                self._gate(exchange_id,'MAC','CHECK_FAIL',refs,before);return self._finish(exchange_id,before,'AUTH_REJECTED','MAC',refs)
            self._gate(exchange_id,'MAC','CHECK_PASS',refs,before)
            if body['channel_id']!=self.channel:
                self._gate(exchange_id,'CHANNEL_ID','CHECK_FAIL',refs,before);return self._finish(exchange_id,before,'AUTH_REJECTED','CHANNEL_ID',refs)
            self._gate(exchange_id,'CHANNEL_ID','CHECK_PASS',refs,before)
            if type(body['sequence']) is not int or body['sequence']!=before+1:
                self._gate(exchange_id,'SEQUENCE','CHECK_FAIL',refs,before);return self._finish(exchange_id,before,'AUTH_REJECTED','SEQUENCE',refs)
            self.sequence+=1;self._gate(exchange_id,'SEQUENCE','CHECK_PASS',refs,before)
            return self._finish(exchange_id,before,'ACCEPTED_INERT','NONE',refs,body)
        except Exception:
            self.close(exchange_id)
            raise


def create_channel(*,session,inventory,channel_id,key_operation_id,left_target_id,right_target_id,execution_gate,public_key=None):
    """Actual socketpair/ephemeral-key acquisition on explicit approved invocation.

    Return key only in memory. Capture never includes key bytes. A deterministic
    public key supplied for calibration is recorded as non-random/public setup.
    """
    require(execution_gate() is None,'RUNTIME_APPROVAL_ABSENT')
    start=session.guard.now();left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC)
    try:
        key=os.urandom(32) if public_key is None else public_key
        require(type(key) is bytes and len(key)==32,'CHANNEL_KEY_BYTES')
        owner=inventory.subject(os.getpid(),session.subject['role'])
        session.add('ENDPOINT_CREATE',{'channel_id':channel_id,'owner':owner,
            'endpoints':[own_descriptor(left.fileno(),left_target_id),own_descriptor(right.fileno(),right_target_id)],
            'key_operation_id':key_operation_id,'random_source_call_succeeded':public_key is None,'key_material_recorded':False},started=start)
        return left,right,key
    except BaseException:
        left.close();right.close();raise
