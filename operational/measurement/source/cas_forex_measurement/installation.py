"""Pinned Linux x86_64 actual Landlock-call capture. Explicit invocation only."""
from __future__ import annotations
import ctypes
import fcntl
import os
import platform
from cas_forex_operational_contracts import capture as c
from cas_forex_operational_contracts.common import canonical_bytes,digest,require,ContractError
from .inventory import stat_record,descriptor

ABI_LAYOUT={'source':'Linux-v6.8-uapi-landlock','machine':'x86_64','create':444,'add':445,'restrict':446,
            'ruleset_size':16,'path_beneath_size':12,'byte_order':'little'}


class NativeInstaller:
    def __init__(self,*,session,inventory,execution_gate,abi_layout_sha256):
        require(abi_layout_sha256==digest(canonical_bytes(ABI_LAYOUT)),'ABI_LAYOUT_PIN')
        self.session,self.inventory,self.gate,self.layout=session,inventory,execution_gate,abi_layout_sha256
        self.used=False
    def install(self, selection):
        c.validate('InstallationSelection',selection)
        require(not self.used,'INSTALL_ONE_SHOT');self.used=True
        require(self.gate() is None,'RUNTIME_APPROVAL_ABSENT')
        require(platform.system()=='Linux' and platform.machine()=='x86_64' and os.geteuid()!=0,'INSTALL_PLATFORM')
        pid=os.getpid();role=self.session.subject['role']
        subject=self.inventory.subject(pid,role)
        require(subject==self.session.subject and subject['pid']==selection['process']['pid'] and subject['start_ticks']==selection['process']['start_ticks'],'INSTALL_SUBJECT')
        tasks=list((self.inventory.proc/str(pid)/'task').iterdir())
        require([p.name for p in tasks]==[str(pid)],'INSTALL_SINGLE_THREAD')
        libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
        libc.prctl.restype=ctypes.c_int;libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
        class Ruleset(ctypes.Structure):_fields_=[('fs',ctypes.c_uint64),('net',ctypes.c_uint64)]
        class Beneath(ctypes.Structure):
            _pack_=1
            _fields_=[('access',ctypes.c_uint64),('parent_fd',ctypes.c_int32)]
        require(ctypes.sizeof(Ruleset)==16 and ctypes.sizeof(Beneath)==12,'ABI_LAYOUT_PIN')
        def call(name,arguments,function,*args):
            require(self.gate() is None,'RUNTIME_APPROVAL_ABSENT');start=self.session.guard.now()
            ctypes.set_errno(0);result=int(function(*args));error=ctypes.get_errno() if result<0 else 0
            end=self.session.guard.clock.stamp()
            self.session.raw(canonical_bytes(arguments),selector='NATIVE_INSTALL_ARGUMENTS',started=start,finished=end,encoding='CANONICAL_JSON')
            self.session.add('INSTALL_CALL',{'subject':subject,'operation':name,'abi_layout_sha256':self.layout,
                'arguments':arguments,'return_value':result,'errno':error},started=start,finished=end)
            self.session.guard.now()
            return result
        abi=call('ABI_QUERY',{'attr_pointer_null':True,'size':0,'flags':1},libc.syscall,444,0,0,1)
        require(abi==selection['abi'] and abi>=4,'INSTALL_ABI_MISMATCH')
        attr=Ruleset(selection['handled_fs'],0);raw=ctypes.string_at(ctypes.byref(attr),16)
        ruleset=call('RULESET_CREATE',{'handled_fs':selection['handled_fs'],'handled_net':0,'size':16,'attr_bytes_hex':raw.hex(),'flags':0},libc.syscall,444,ctypes.byref(attr),16,0)
        require(ruleset>=0,'INSTALL_CREATE_FAILED')
        opened=[];cleanup_failed=False
        try:
            targets={row['target_id']:row for row in selection['targets']}
            require(len(targets)==len(selection['targets'])==len(selection['rules']),'INSTALL_TARGET_SET')
            for rule in selection['rules']:
                target=targets[rule['target_id']];start=self.session.guard.now();flags=os.O_PATH|os.O_CLOEXEC|os.O_NOFOLLOW
                fd=-1;error=0;st=None;link=None
                try:
                    fd=os.open(target['resolved_path'],flags);opened.append((fd,target['target_id']))
                    st=os.fstat(fd);resolved=os.readlink('/proc/self/fd/'+str(fd)).encode()
                    link=self.session.raw(resolved,selector='FD_LINK',started=start,finished=self.session.guard.now())
                except OSError as exc:error=exc.errno
                self.session.add('RULE_TARGET_OPEN',{'target_id':target['target_id'],'selected_path':target['resolved_path'],
                    'access_mask':rule['rights'],'open_flags':flags,'returned_fd':fd,'errno':error,
                    'stat':stat_record(st) if st else None,'resolved_link_ref':link},started=start)
                require(fd>=0 and error==0 and (st.st_dev,st.st_ino)==(target['device'],target['inode']) and resolved.decode()==target['resolved_path'],'INSTALL_TARGET_MISMATCH')
                item=Beneath(rule['rights'],fd);native=ctypes.string_at(ctypes.byref(item),12)
                result=call('ADD_PATH_RULE',{'ruleset_fd':ruleset,'rule_type':1,'allowed_access':rule['rights'],
                    'parent_fd':fd,'attr_bytes_hex':native.hex(),'flags':0},libc.syscall,445,ruleset,1,ctypes.byref(item),0)
                require(result==0,'INSTALL_ADD_FAILED')
            require(call('PR_SET_NO_NEW_PRIVS',{'option':38,'value':1,'arg3':0,'arg4':0,'arg5':0},libc.prctl,38,1,0,0,0)==0,'INSTALL_NNP_FAILED')
            require(call('RESTRICT_SELF',{'ruleset_fd':ruleset,'flags':0},libc.syscall,446,ruleset,0)==0,'INSTALL_RESTRICT_FAILED')
            require(call('PR_GET_NO_NEW_PRIVS',{'option':39,'arg2':0,'arg3':0,'arg4':0,'arg5':0},libc.prctl,39,0,0,0,0)==1,'INSTALL_NNP_READBACK')
        finally:
            for fd,target in [*opened,(ruleset,'installation-ruleset')]:
                start=self.session.guard.clock.stamp();identity=None;ret=-1;error=0
                try:
                    st=os.fstat(fd);flags=fcntl.fcntl(fd,fcntl.F_GETFL)|os.O_CLOEXEC
                    identity=descriptor(fd,st,flags,target)
                except OSError:cleanup_failed=True
                try:os.close(fd);ret=0
                except OSError as exc:error=exc.errno;cleanup_failed=True
                if identity is not None:
                    try:self.session.add('CLOSE',{'exchange_id':None,'descriptor':identity,'return_value':ret,'errno':error},started=start,finished=self.session.guard.clock.stamp())
                    except Exception:cleanup_failed=True
            if cleanup_failed:raise ContractError('INSTALL_CLEANUP_UNCONFIRMED')
        return self.session.operations[-1]['finished']
