"""Bounded Linux reads, selected asset hashing and observed paused child creation."""
from __future__ import annotations
import fcntl
import hashlib
import os
from pathlib import Path
import signal
import stat
import subprocess
import time
from cas_forex_operational_contracts import capture as c
from cas_forex_operational_contracts.common import canonical_bytes,decode_canonical,digest,require,safe_path,ContractError,MAX_OBJECT


def parse_stat(raw):
    text=raw.decode('ascii'); end=text.rfind(') ')
    require(end>0,'PROC_STAT')
    fields=text[end+2:].split()
    require(len(fields)>19,'PROC_STAT')
    return {'pid':int(text.split(' ',1)[0]),'state':fields[0],'parent_pid':int(fields[1]),'start_ticks':int(fields[19])}


def stat_record(st):
    return {'device':st.st_dev,'inode':st.st_ino,'mode':st.st_mode,'uid':st.st_uid,'gid':st.st_gid,
            'bytes':st.st_size,'mtime_ns':st.st_mtime_ns,'ctime_ns':st.st_ctime_ns}


def descriptor(fd,st,flags,target):
    kind='REGULAR' if stat.S_ISREG(st.st_mode) else 'SOCKET' if stat.S_ISSOCK(st.st_mode) else 'PIPE' if stat.S_ISFIFO(st.st_mode) else 'CHAR' if stat.S_ISCHR(st.st_mode) else 'ANON' if st.st_nlink==0 else 'OTHER'
    return {'fd':fd,'object_type':kind,'device':st.st_dev,'inode':st.st_ino,'access_flags':flags&~os.O_CLOEXEC,
            'close_on_exec':bool(flags&os.O_CLOEXEC),'selected_target_id':target}


def require_owned_child_lifecycle():
    # A failed pidfd_open must not strand the child. Default SIGCHLD plus one
    # parent thread ensures our unreaped child PID cannot be reused underneath
    # the guarded waitid(WNOWAIT)/kill fallback below.
    require(signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL and len(os.listdir('/proc/self/task'))==1,
            'OWNED_CHILD_LIFECYCLE_UNAVAILABLE')


def terminate_owned_child(pid,pidfd=None):
    """Bounded error cleanup, never an accepted retirement observation."""
    if pidfd is not None:
        try:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
        except OSError:pass
    else:
        require_owned_child_lifecycle()
        try:observed=os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        except ChildProcessError:return False
        if observed is None:
            # A live direct child has not been reaped; its PID is still reserved.
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
    end=time.monotonic()+1.0
    while time.monotonic()<end:
        try:got,_=os.waitpid(pid,os.WNOHANG)
        except ChildProcessError:return False
        if got:return True
        time.sleep(0.005)
    return False


class LinuxInventory:
    def __init__(self, *, proc_root=Path('/proc'), maximum_read=1_048_576):
        require(0<maximum_read<=MAX_OBJECT,'READ_LIMIT');self.proc=Path(proc_root);self.maximum=maximum_read
    def read(self,path):
        with Path(path).open('rb') as f:raw=f.read(self.maximum+1)
        require(len(raw)<=self.maximum,'RAW_OVERFLOW');return raw
    def subject(self,pid,role):
        before=parse_stat(self.read(self.proc/str(pid)/'stat'))
        status=self.read(self.proc/str(pid)/'status').decode('ascii')
        values={line.split(':',1)[0]:line.split(':',1)[1].split() for line in status.splitlines() if ':' in line}
        uid=[int(x) for x in values['Uid']];gid=[int(x) for x in values['Gid']]
        require(len(set(uid))==len(set(gid))==1,'CREDENTIAL_AMBIGUITY')
        parent=parse_stat(self.read(self.proc/str(before['parent_pid'])/'stat'))
        after=parse_stat(self.read(self.proc/str(pid)/'stat'))
        require(all(before[k]==after[k] for k in ('pid','parent_pid','start_ticks')) and after['state'] not in ('Z','X'),'PROCESS_CHANGED')
        result={'role':role,'boot_id':self.read(self.proc/'sys/kernel/random/boot_id').decode().strip(),
                'pid':pid,'start_ticks':before['start_ticks'],'parent_pid':before['parent_pid'],
                'parent_start_ticks':parent['start_ticks'],'uid':uid[0],'gid':gid[0]}
        c.validate('CaptureSubject',result);return result
    def proc_read(self,pid,selector,argument,*,session,role):
        mapping={'STAT':'stat','STATUS':'status','MOUNTINFO':'mountinfo','NET_TCP':'net/tcp','NET_TCP6':'net/tcp6'}
        root=self.proc/str(pid);start=session.guard.now();subject=self.subject(pid,role)
        if selector in mapping:path=root/mapping[selector]
        elif selector=='TASK_STAT':require(argument.isdigit(),'PROC_SELECTOR');path=root/'task'/argument/'stat'
        elif selector in ('FD_LINK','FDINFO'):require(argument.isdigit(),'PROC_SELECTOR');path=root/('fd' if selector=='FD_LINK' else 'fdinfo')/argument
        elif selector=='NAMESPACE_LINK':require(argument in ('mnt','pid','net','time','user','ipc','uts','cgroup'),'PROC_SELECTOR');path=root/'ns'/argument
        elif selector=='EXE_LINK':path=root/'exe'
        else:raise ContractError('PROC_SELECTOR')
        try:raw=os.readlink(path).encode() if selector.endswith('_LINK') else self.read(path)
        except OSError as exc:
            raise ContractError('PROC_READ_UNAVAILABLE') from None
        end=session.guard.now();ref=session.raw(raw,selector=selector,started=start,finished=end,subject=subject)
        require(ref is not None,'PROC_EMPTY')
        session.add('PROC_READ',{'subject':subject,'selector':selector,'selector_argument':argument,
                    'raw_ref':ref,'return_value':len(raw),'errno':0},started=start,finished=end)
        return ref,raw
    def boundary(self,pid,*,role,session):
        start=session.guard.now();subject=self.subject(pid,role)
        parent=self.subject(subject['parent_pid'],'CONTROLLER' if role=='DECISION_BOOTSTRAP' else 'DECISION_BOOTSTRAP' if role in ('MODEL_BOOTSTRAP','MODEL_SERVICE') else 'CONTROLLER')
        # Retain the parent evidence through existing PROC_READ operations. The
        # boundary body has no parent raw-ref fields; authenticated batch membership
        # and each operation's exact subject bind these supporting observations.
        _,parent_before=self.proc_read(parent['pid'],'STAT',None,session=session,role=parent['role'])
        before,_=self.proc_read(pid,'STAT',None,session=session,role=role)
        status,_=self.proc_read(pid,'STATUS',None,session=session,role=role)
        tasks=sorted(x.name for x in (self.proc/str(pid)/'task').iterdir())
        require(0<len(tasks)<=256 and all(x.isdigit() for x in tasks),'TASK_INVENTORY')
        refs=[self.proc_read(pid,'TASK_STAT',tid,session=session,role=role)[0] for tid in tasks]
        ns=[]
        for name in ('mnt','pid','net','time','user','ipc','uts','cgroup'):
            ref,raw=self.proc_read(pid,'NAMESPACE_LINK',name,session=session,role=role)
            st=(self.proc/str(pid)/'ns'/name).stat()
            ns.append({'namespace':name,'link_text':raw.decode(),'device':st.st_dev,'inode':st.st_ino,'raw_ref':ref})
        mount,mount_raw=self.proc_read(pid,'MOUNTINFO',None,session=session,role=role)
        exe,exe_raw=self.proc_read(pid,'EXE_LINK',None,session=session,role=role)
        executable=stat_record((self.proc/str(pid)/'exe').stat())
        after,_=self.proc_read(pid,'STAT',None,session=session,role=role)
        _,parent_after=self.proc_read(parent['pid'],'STAT',None,session=session,role=parent['role'])
        require(parent==self.subject(parent['pid'],parent['role']) and subject['parent_start_ticks']==parent['start_ticks']
            and all(parse_stat(raw)[key]==parent[key] for raw in (parent_before,parent_after)
                    for key in ('pid','parent_pid','start_ticks')),'PARENT_CHANGED')
        require(subject==self.subject(pid,role) and tasks==sorted(x.name for x in (self.proc/str(pid)/'task').iterdir()),'PROCESS_CHANGED')
        require(self.read(self.proc/str(pid)/'mountinfo')==mount_raw and os.readlink(self.proc/str(pid)/'exe').encode()==exe_raw
            and stat_record((self.proc/str(pid)/'exe').stat())==executable,'PROCESS_IMAGE_CHANGED')
        for row in ns:
            target=self.proc/str(pid)/'ns'/row['namespace'];st=target.stat()
            require(os.readlink(target)==row['link_text'] and (st.st_dev,st.st_ino)==(row['device'],row['inode']),'NAMESPACE_CHANGED')
        body={'subject':subject,'parent_subject':parent,'before_stat_ref':before,'after_stat_ref':after,
            'status_ref':status,'task_stat_refs':refs,'namespace_reads':ns,'mountinfo_ref':mount,
            'exe_link_ref':exe,'exe_stat':executable}
        return session.add('PROCESS_BOUNDARY',body,started=start),body
    def _reused_boundary(self, snapshot, *, session):
        ref,body=snapshot
        require(ref['artifact_kind']=='CANONICAL_PAYLOAD','BOUNDARY_REFERENCE_KIND')
        op=c.decode('CaptureOperation',session.sink.readback(ref)).payload()
        require(op['kind']=='PROCESS_BOUNDARY' and op['data']==body and op in session.operations,'BOUNDARY_NOT_IN_CURRENT_SESSION')
        return ref,body,op['started']
    def descriptors(self,pid,*,role,session,paused_boundary_id,targets,require_stopped=True,boundary_snapshot=None):
        if boundary_snapshot is None:
            start=session.guard.now();before,boundary=self.boundary(pid,role=role,session=session)
        else:
            before,boundary,start=self._reused_boundary(boundary_snapshot,session=session)
            require(boundary['subject']==self.subject(pid,role),'REUSED_BOUNDARY_PROCESS_CHANGED')
        state=parse_stat(self.read(self.proc/str(pid)/'stat'))['state']
        require(not require_stopped or state in ('T','t'),'CHILD_NOT_PAUSED')
        base=self.proc/str(pid)/'fd';fds=sorted(int(p.name) for p in base.iterdir())
        require(len(fds)<=16 and set(fds)==set(targets),'DESCRIPTOR_IDENTITY_MISMATCH')
        rows=[]
        for fd in fds:
            link,_=self.proc_read(pid,'FD_LINK',str(fd),session=session,role=role)
            info,raw=self.proc_read(pid,'FDINFO',str(fd),session=session,role=role)
            flags=[x.split(':',1)[1].strip() for x in raw.decode().splitlines() if x.startswith('flags:')]
            require(len(flags)==1,'FDINFO_FLAGS');st=(base/str(fd)).stat()
            rows.append({'descriptor':descriptor(fd,st,int(flags[0],8),targets[fd]),'link_ref':link,'fdinfo_ref':info,
                'stat':stat_record(st),'fstat_return':0,'fstat_errno':0})
        if boundary_snapshot is None:after,_=self.boundary(pid,role=role,session=session)
        else:
            # Both references intentionally name one retained earlier snapshot.
            # They are not claims of two recaptures. Actual live subject equality
            # and complete FD re-enumeration are checked under its common interval.
            require(boundary['subject']==self.subject(pid,role),'REUSED_BOUNDARY_PROCESS_CHANGED')
            after=before
        require(fds==sorted(int(p.name) for p in base.iterdir()),'DESCRIPTOR_INVENTORY_CHANGED')
        for row in rows:
            fd=row['descriptor']['fd'];info=self.read(self.proc/str(pid)/'fdinfo'/str(fd)).decode()
            flags=int(next(x.split(':',1)[1] for x in info.splitlines() if x.startswith('flags:')),8)
            require(stat_record((base/str(fd)).stat())==row['stat'] and descriptor(fd,(base/str(fd)).stat(),flags,targets[fd])==row['descriptor'],'DESCRIPTOR_CHANGED')
        body={'subject':boundary['subject'],'paused_boundary_id':paused_boundary_id,'before_process_ref':before,
              'after_process_ref':after,'enumerated_fds':fds,'entries':rows,'enumeration_complete':True}
        return session.add('FD_INVENTORY',body,started=start),body
    def listener(self,pid,*,role,port,session,targets,boundary_id,boundary_snapshot=None):
        if boundary_snapshot is None:
            start=session.guard.now();process,_=self.boundary(pid,role=role,session=session)
        else:process,_,start=self._reused_boundary(boundary_snapshot,session=session)
        inventory,body=self.descriptors(pid,role=role,session=session,paused_boundary_id=boundary_id,targets=targets,
            require_stopped=False,boundary_snapshot=boundary_snapshot)
        table,raw=self.proc_read(pid,'NET_TCP',None,session=session,role=role)
        candidates=[]
        for line in raw.decode('ascii').splitlines()[1:]:
            fields=line.split()
            if len(fields)>9 and fields[3]=='0A' and fields[1]==f'0100007F:{port:04X}':
                candidates.extend(x['descriptor'] for x in body['entries'] if x['descriptor']['object_type']=='SOCKET' and x['descriptor']['inode']==int(fields[9]))
        require(len(candidates)==1,'LISTENER_OWNERSHIP_UNAVAILABLE')
        data={'subject':body['subject'],'address':'127.0.0.1','port':port,'socket_descriptor':candidates[0],
              'process_snapshot_ref':process,'tcp_table_ref':table,'fd_inventory_ref':inventory}
        return session.add('LISTENER_READ',data,started=start)
    def hash_asset(self,selected,*,session,mount_evidence):
        c.validate('AssetSelection',selected);safe_path(selected['path'],absolute=True)
        start=session.guard.now();fd=os.open(selected['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before=os.fstat(fd);require(stat.S_ISREG(before.st_mode),'ASSET_TYPE')
            # Independent read-only mount evidence is supplied and read back, never inferred from O_RDONLY.
            raw=session.sink.readback(mount_evidence);require(mount_evidence['artifact_kind']=='MOUNT_INVENTORY','MOUNT_EVIDENCE')
            normalized=decode_canonical(raw);require(set(normalized)=={'mountinfo_utf8'},'MOUNT_EVIDENCE_SHAPE')
            require(normalized['mountinfo_utf8'].encode()==self.read(self.proc/'self/mountinfo'),'MOUNT_EVIDENCE_CURRENT')
            require(os.statvfs(selected['path']).f_flag & os.ST_RDONLY,'ASSET_NOT_READONLY_MOUNT')
            h=hashlib.sha256();count=0
            while True:
                session.guard.now();block=os.read(fd,1_048_576)
                if not block:break
                count+=len(block);require(count<=selected['bytes'],'ASSET_SIZE');h.update(block)
            after=os.fstat(fd)
            require(normalized['mountinfo_utf8'].encode()==self.read(self.proc/'self/mountinfo'),'MOUNT_EVIDENCE_CHANGED')
            require(stat_record(before)==stat_record(after),'ASSET_CHANGED')
            require((count,h.hexdigest(),after.st_dev,after.st_ino)==(selected['bytes'],selected['sha256'],selected['device'],selected['inode']),'ASSET_IDENTITY_MISMATCH')
        finally:os.close(fd)
        end=session.guard.now()
        data={'asset_id':selected['asset_id'],'selected_path':selected['path'],'fd_stat_before':stat_record(before),
            'fd_stat_after':stat_record(after),'opened_read_only':True,'mount_read_only_evidence_ref':mount_evidence,
            'bytes_read':count,'content_sha256':h.hexdigest(),'hash_started':start,'hash_finished':end}
        return session.add('FILE_HASH',data,started=start,finished=end)


def pause_bootstrap_before_private_work():
    """Integration must call first in the separately pinned single-thread bootstrap."""
    os.kill(os.getpid(),signal.SIGSTOP)


class PausedSpawner:
    def __init__(self,*,inventory,session,execution_gate):
        self.inventory,self.session,self.gate=inventory,session,execution_gate
        self.children={}
    def spawn(self, *, spawn_id,role,argv,environment,cwd,component_sha256,executable_asset_id,policy_sha256,descriptor_bindings):
        require(role in ('RUNNER_INSTALL','MODEL_INSTALL') and type(argv) in (list,tuple) and argv and all(type(x) is str and '\x00' not in x for x in argv),'SPAWN_COMMAND')
        safe_path(argv[0],absolute=True);safe_path(cwd,absolute=True)
        require(type(environment) is dict and all(type(k) is str and type(v) is str and '\x00' not in k+v and '=' not in k for k,v in environment.items()),'SPAWN_ENVIRONMENT')
        require(self.gate() is None,'RUNTIME_APPROVAL_ABSENT')
        start=self.session.guard.now();parent=self.inventory.subject(os.getpid(),'CONTROLLER' if role=='RUNNER_INSTALL' else 'DECISION_BOOTSTRAP')
        for binding in descriptor_bindings:
            c.validate('SpawnDescriptor',binding)
            st=os.fstat(binding['parent_fd']);flags=fcntl.fcntl(binding['parent_fd'],fcntl.F_GETFL)
            flags|=os.O_CLOEXEC if fcntl.fcntl(binding['parent_fd'],fcntl.F_GETFD)&fcntl.FD_CLOEXEC else 0
            actual=descriptor(binding['parent_fd'],st,flags,binding['target_id'])
            expected=dict(binding['object_identity']);expected['fd']=binding['parent_fd']
            require(actual==expected,'PARENT_DESCRIPTOR_MISMATCH')
        require(len({x['child_fd'] for x in descriptor_bindings})==len(descriptor_bindings),'SPAWN_DESCRIPTOR_DUPLICATE')
        stdio={};passed=[]
        for row in descriptor_bindings:
            if row['inheritance']=='STDIO_DUP':require(row['child_fd'] in (0,1,2),'SPAWN_STDIO');stdio[row['child_fd']]=row['parent_fd']
            else:require(row['parent_fd']==row['child_fd'],'PASS_FD_RENUMBER');passed.append(row['parent_fd'])
        require(set(stdio)=={0,1,2},'EXPLICIT_STDIO_REQUIRED')
        require_owned_child_lifecycle()
        process=subprocess.Popen(argv,executable=argv[0],env=dict(environment),cwd=cwd,stdin=stdio[0],stdout=stdio[1],stderr=stdio[2],
                                 close_fds=True,pass_fds=tuple(passed),shell=False)
        self.children[spawn_id]=process
        pidfd=None
        try:
            pidfd=os.pidfd_open(process.pid)
            while True:
                self.session.guard.now();pid,status=os.waitpid(process.pid,os.WNOHANG|os.WUNTRACED)
                if pid:
                    require(os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGSTOP,'CHILD_DID_NOT_PAUSE');break
                time.sleep(min(0.005,self.session.guard.remaining()))
            child_role='DECISION_BOOTSTRAP' if role=='RUNNER_INSTALL' else 'MODEL_BOOTSTRAP'
            child=self.inventory.subject(process.pid,child_role)
            boundary,_=self.inventory.boundary(process.pid,role=child_role,session=self.session)
            data={'spawn_id':spawn_id,'role':role,'parent':parent,'selected_component_sha256':component_sha256,
                'selected_executable_asset_id':executable_asset_id,'selected_policy_sha256':policy_sha256,
                'descriptor_bindings':descriptor_bindings,'returned_pid':process.pid,'errno':0,
                'paused_child':child,'child_process_boundary_ref':boundary,'result':'SPAWNED_AND_PAUSED'}
            self.session.add('SPAWN',data,started=start)
            targets={x['child_fd']:x['target_id'] for x in descriptor_bindings}
            _,observed=self.inventory.descriptors(process.pid,role=child_role,session=self.session,paused_boundary_id=spawn_id,targets=targets)
            expected=[]
            for row in descriptor_bindings:
                item=dict(row['object_identity']);item['fd']=row['child_fd'];item['close_on_exec']=False;expected.append(item)
            require(sorted((x['descriptor'] for x in observed['entries']),key=lambda x:x['fd'])==sorted(expected,key=lambda x:x['fd']),'CHILD_DESCRIPTOR_MISMATCH')
            return process,child
        except BaseException:
            terminate_owned_child(process.pid,pidfd)
            raise
        finally:
            if pidfd is not None:os.close(pidfd)

    def resume(self,spawn_id,*,expected_subject):
        process=self.children[spawn_id];self.session.guard.now()
        require(self.inventory.subject(process.pid,expected_subject['role'])==expected_subject,'PROCESS_CHANGED')
        os.kill(process.pid,signal.SIGCONT)
