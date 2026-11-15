"""Actual-call recording, content retention and exact accepted CapturePort adapters.

No authority, clock, process or store is activated by construction. Measurement
is trusted adapter reporting, not kernel tracing or an authenticated decision.
"""
from __future__ import annotations
from datetime import datetime, timezone
import os
import stat
import fcntl
from pathlib import Path
import threading
import time
from cas_forex_operational_contracts import capture as c, method as m
from cas_forex_operational_contracts.common import (ContractError, DependencyUnavailable,
    canonical_bytes, decode_canonical, digest, require, safe_path, utc, MAX_OBJECT)
from cas_forex_operational_contracts.validation import verify_reference_bytes


def snapshot(value):
    return decode_canonical(canonical_bytes(value,limit=MAX_OBJECT),limit=MAX_OBJECT)


class LinuxClock:
    def domain(self):
        return {'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'time_namespace_inode':os.stat('/proc/self/ns/time').st_ino,'clock_id':'CLOCK_BOOTTIME'}
    def stamp(self):
        return {'utc':datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                'boottime_ns':time.clock_gettime_ns(time.CLOCK_BOOTTIME)}


class OriginalClock:
    def __init__(self, budget, *, clock, execution_gate, drift_ns=1_000_000_000):
        self.budget=m.validate('SetupBudget',budget).payload()
        require(callable(execution_gate) and type(drift_ns) is int and 0<=drift_ns<=1_000_000_000,'CLOCK_CONFIG')
        self.clock,self.gate,self.drift=clock,execution_gate,drift_ns
        self.last=None
    def now(self):
        require(self.gate() is None,'INVALID_EXECUTION_GATE')
        require(self.clock.domain()==self.budget['clock_domain'],'CLOCK_DOMAIN_UNSUPPORTED')
        stamp=m.validate('Stamp',self.clock.stamp()).payload()
        begin,end,outer=(self.budget[k] for k in ('started','deadline','outer_deadline'))
        require(begin['boottime_ns']<=stamp['boottime_ns']<min(end['boottime_ns'],outer['boottime_ns']),'SETUP_DEADLINE_EXPIRED')
        require(utc(begin['utc'])<=utc(stamp['utc'])<min(utc(end['utc']),utc(outer['utc'])),'SETUP_DEADLINE_EXPIRED')
        elapsed_utc=int((utc(stamp['utc'])-utc(begin['utc'])).total_seconds()*1_000_000_000)
        require(abs(elapsed_utc-(stamp['boottime_ns']-begin['boottime_ns']))<=self.drift,'CLOCK_DRIFT')
        if self.last:
            require(stamp['boottime_ns']>=self.last['boottime_ns'] and utc(stamp['utc'])>=utc(self.last['utc']),'CLOCK_DRIFT')
        self.last=snapshot(stamp)
        return stamp
    def remaining(self):
        now=self.now()
        return min((self.budget['deadline']['boottime_ns']-now['boottime_ns'])/1e9,
                   (utc(self.budget['deadline']['utc'])-utc(now['utc'])).total_seconds())


class DirectoryCaptureSink:
    """Explicit writes to an existing externally selected retention directory.

    No directory creation, appointment, signing or protected-registry initialization.
    Root authorization/immutability belongs to the selected retention authority.
    """
    def __init__(self, root, *, execution_gate, maximum_bytes=67_108_864):
        safe_path(str(root),absolute=True)
        require(callable(execution_gate) and 0<maximum_bytes<=67_108_864,'SINK_CONFIG')
        self.root=Path(root); self.gate=execution_gate; self.maximum=maximum_bytes
        self.lock=threading.Lock()
    def _root(self):
        require(self.gate() is None,'INVALID_EXECUTION_GATE')
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        return fd
    def retain(self, raw: bytes, *, artifact_kind: m.ArtifactKind) -> m.ObjectRef:
        require(type(raw) is bytes and 0<len(raw)<=MAX_OBJECT,'RAW_BYTES_BOUND')
        ref={'object_id':digest(raw),'bytes':len(raw),'sha256':digest(raw),'artifact_kind':artifact_kind}
        m.validate('ObjectRef',ref)
        with self.lock:
            root=self._root()
            try:
                fcntl.flock(root,fcntl.LOCK_EX)
                # Bounded existing directory; never discard an unrecognized entry.
                names=os.listdir(root)
                require(len(names)<=4096,'RETENTION_CAPACITY')
                used=0
                for name in names:
                    st=os.stat(name,dir_fd=root,follow_symlinks=False)
                    require(len(name)==64 and all(x in '0123456789abcdef' for x in name)
                            and stat.S_ISREG(st.st_mode),'RETENTION_ENTRY')
                    used+=st.st_size
                if ref['object_id'] in names:
                    require(self.readback(ref)==raw,'RETENTION_CONFLICT');return ref
                try:
                    require(used+len(raw)<=self.maximum,'RETENTION_CAPACITY')
                    fd=os.open(ref['object_id'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=root)
                except FileExistsError:
                    require(self.readback(ref)==raw,'RETENTION_CONFLICT'); return ref
                try:
                    view=memoryview(raw)
                    while view:
                        count=os.write(fd,view); require(count>0,'RETENTION_WRITE'); view=view[count:]
                    os.fsync(fd)
                finally:os.close(fd)
                os.fsync(root)
            finally:os.close(root)
        require(self.readback(ref)==raw,'RETENTION_READBACK')
        return ref
    def readback(self, reference: m.ObjectRef) -> bytes:
        ref=m.validate('ObjectRef',reference).payload(); root=self._root()
        try:fd=os.open(ref['object_id'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=root)
        finally:os.close(root)
        try:
            st=os.fstat(fd); require(stat.S_ISREG(st.st_mode) and st.st_size==ref['bytes'],'RAW_BYTES_MISMATCH')
            result=bytearray()
            while len(result)<=ref['bytes']:
                block=os.read(fd,min(65536,ref['bytes']+1-len(result)))
                if not block:break
                result.extend(block)
        finally:os.close(fd)
        raw=bytes(result); verify_reference_bytes(ref,raw)
        return raw


class CaptureSession:
    """Synchronous operation indices are allocated at actual adapter call boundaries."""
    def __init__(self, *, budget, producer_id, origin, evidence_class, subject,
                 guard, sink, capture_id, receiver_component_sha256=None,
                 previous_batch_sha256='0'*64):
        self.budget=m.validate('SetupBudget',budget).payload()
        self.subject=c.validate('CaptureSubject',subject).payload()
        self.guard,self.sink=guard,sink
        self.meta=dict(capture_id=capture_id,producer_id=producer_id,reporting_origin=origin,
            evidence_class=evidence_class,receiver_component_sha256=receiver_component_sha256,
            previous_batch_sha256=previous_batch_sha256)
        self.operations=[];self.blob_manifests=[];self.started=None;self.sealed=False;self.raw_bytes=0
        self.lock=threading.RLock()
    def raw(self, value: bytes, *, selector, started, finished, encoding='BINARY', subject=None):
        require(not self.sealed and type(value) is bytes and len(value)<=MAX_OBJECT,'CAPTURE_BOUNDS')
        require(self.raw_bytes+len(value)<=67_108_864,'CAPTURE_BOUNDS')
        self.raw_bytes+=len(value)
        ref=self.sink.retain(value,artifact_kind='NATIVE_CAPTURE_BYTES') if value else None
        manifest={'format':'forex.raw-capture-blob/1','binding':self.budget['binding'],
            'budget_sha256':digest(canonical_bytes(self.budget)),'producer_id':self.meta['producer_id'],
            'origin':self.meta['reporting_origin'],'subject':subject or self.subject,'started':started,'finished':finished,
            'blob_ref':ref,'encoding':encoding,'source_selector':selector,'raw_bytes':len(value),'raw_sha256':digest(value)}
        c.validate('RawBlobManifest',manifest)
        manifest_ref=self.sink.retain(canonical_bytes(manifest),artifact_kind='RAW_BLOB_MANIFEST')
        self.blob_manifests.append(manifest_ref)
        return ref
    def add(self, kind, data, *, started, finished=None):
        with self.lock:
            require(not self.sealed and len(self.operations)<4096,'CAPTURE_BOUNDS')
            end=finished or self.guard.now()
            if self.started is None or started['boottime_ns']<self.started['boottime_ns']:self.started=started
            item={'operation_index':len(self.operations)+1,'kind':kind,'started':started,'finished':end,'data':snapshot(data)}
            c.validate('CaptureOperation',item)
            self.operations.append(item)
            return self.sink.retain(canonical_bytes(item),artifact_kind='CANONICAL_PAYLOAD')
    def seal(self):
        require(not self.sealed and self.operations,'CAPTURE_EMPTY_OR_SEALED')
        result={'format':'forex.trusted-setup-capture/2','binding':self.budget['binding'],
            'budget_sha256':digest(canonical_bytes(self.budget)),**self.meta,'subject':self.subject,
            'started':self.started,'finished':self.guard.now(),'operations':snapshot(self.operations)}
        c.validate('CaptureBatch',result)
        self.sink.retain(canonical_bytes(result),artifact_kind='TRUSTED_CAPTURE_BATCH')
        self.sealed=True
        return result


class ActualCaptureAdapter:
    """Drain real, separately originated sessions and acquire selected current roles.

    Authenticator callbacks are authority-owned exact-byte checks returning None.
    They may not be selected by records or replaced with a positive default.
    """
    def __init__(self, *, sessions, inventory, authenticate_spawn, authenticate_exposed,
                 current_subjects, session_factory):
        require(all(callable(x) for x in (authenticate_spawn,authenticate_exposed,current_subjects,session_factory)),'CAPTURE_DEPENDENCY')
        self.sessions=tuple(sessions);self.inventory=inventory
        self.auth_spawn=authenticate_spawn;self.auth_exposed=authenticate_exposed
        self.current_subjects=current_subjects;self.session_factory=session_factory
        self.used=False
    def capture_setup(self, plan: m.CoveragePlan, original_budget: m.SetupBudget,
                      selected_spawns: tuple[c.SpawnSelection,...], *, sink: c.CaptureSinkPort) -> tuple[c.CaptureBatch,...]:
        require(not self.used,'CAPTURE_ALREADY_CONSUMED')
        m.validate('CoveragePlan',plan);m.validate('SetupBudget',original_budget)
        require(digest(canonical_bytes(plan))==original_budget['coverage_plan_sha256'],'CONTEXT_MISMATCH')
        for spawn in selected_spawns:
            c.validate('SpawnSelection',spawn)
            require(self.auth_spawn(spawn,original_budget) is None,'SPAWN_AUTHENTICATION')
            require(spawn['binding']==original_budget['binding'] and spawn['budget_sha256']==digest(canonical_bytes(original_budget)),'CONTEXT_MISMATCH')
        require(self.sessions,'RAW_EVIDENCE_UNAVAILABLE')
        result=[]
        require(sum(x.raw_bytes for x in self.sessions)<=plan['max_raw_bytes'],'CAPTURE_PLAN_BYTE_LIMIT')
        for session in self.sessions:
            require(session.budget==original_budget and session.sink is sink,'CONTEXT_MISMATCH')
            result.append(session.seal())
        self.used=True
        return tuple(result)
    def capture_current_roles(self, accepted: m.ExposedOutput, plan: m.CoveragePlan, original_budget: m.SetupBudget, *,
                              sink: c.CaptureSinkPort) -> tuple[c.CaptureBatch,...]:
        m.validate('ExposedOutput',accepted);m.validate('CoveragePlan',plan)
        require(accepted['kind']=='METHOD_DECISION' and accepted['binding']==original_budget['binding'],'CONTEXT_MISMATCH')
        require(self.auth_exposed(accepted,plan,original_budget) is None,'EXPOSED_AUTHENTICATION')
        result=[]
        # This route creates fresh readbacks only. No event append, budget reset or ACK.
        subjects=tuple(self.current_subjects(accepted))
        require(len(subjects)==3 and {x['role'] for x in subjects}=={'CONTROLLER','DECISION_BOOTSTRAP','MODEL_SERVICE'},'CURRENT_ROLE_SELECTION')
        for selected in subjects:
            session=self.session_factory(selected,original_budget,sink)
            require(session.budget==original_budget and session.sink is sink and session.subject['pid']==selected['pid']
                and session.subject['role']==selected['role'],'CURRENT_SESSION_SELECTION')
            boundary=self.inventory.boundary(selected['pid'],role=selected['role'],session=session)
            if selected['role'] in ('CONTROLLER','DECISION_BOOTSTRAP'):
                fd=selected.get('channel_fd')
                require(type(fd) is int and fd>=0,'CURRENT_CHANNEL_SELECTION')
                for selector in ('FD_LINK','FDINFO'):
                    self.inventory.proc_read(selected['pid'],selector,str(fd),session=session,role=selected['role'])
            else:
                require(type(selected.get('listener_port')) is int,'CURRENT_LISTENER_SELECTION')
                self.inventory.listener(selected['pid'],role=selected['role'],port=selected['listener_port'],session=session,
                    targets=selected['descriptor_targets'],boundary_id=selected['boundary_id'],boundary_snapshot=boundary)
            result.append(session.seal())
        require(result,'RAW_EVIDENCE_UNAVAILABLE')
        return tuple(result)
