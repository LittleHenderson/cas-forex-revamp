"""Read-only root producer for the reviewed per-process namespace proof.

Import is inert. The independently approved launcher must call this only after
its actual subject/config/admission binding, then retain the proof inside its
protected launch receipt. This helper issues no approval and starts nothing.
"""
from datetime import datetime, timezone
import os
import re
import sys
import time

def require(condition, reason):
    if not condition: raise RuntimeError(reason)

def _read(path, maximum):
    with open(path, 'rb', buffering=0) as stream:
        chunks=[];total=0
        while True:
            piece=stream.read(maximum+1-total)
            if not piece:break
            chunks.append(piece);total+=len(piece)
            require(total<=maximum,'NAMESPACE_NATIVE_READ_BOUND')
        raw=b''.join(chunks)
    require(0 < len(raw) <= maximum, 'NAMESPACE_NATIVE_READ_BOUND')
    return raw

def _process(pid):
    require(type(pid) is int and pid > 0, 'NAMESPACE_PID')
    raw=_read('/proc/'+str(pid)+'/stat',65536)
    tail=raw[raw.rfind(b')')+2:].split()
    require(len(tail)>=20 and tail[0] not in (b'Z',b'X'), 'NAMESPACE_PROCESS_NOT_LIVE')
    return {'pid':pid,'start_ticks':int(tail[19]),'uid':os.stat('/proc/'+str(pid)).st_uid}

def _row(pid):
    before=_process(pid)
    name='/proc/'+str(pid)+'/ns/user'
    first=os.stat(name)
    raw=_read('/proc/'+str(pid)+'/uid_map',256)
    last=os.stat(name)
    require((first.st_dev,first.st_ino)==(last.st_dev,last.st_ino)
            and _process(pid)==before, 'NAMESPACE_NATIVE_IDENTITY_CHANGED')
    require(raw.split()==[b'0',b'0',b'4294967295'], 'NAMESPACE_NOT_HOST_IDENTITY_MAP')
    return {'process':before,'state':{'device':first.st_dev,'inode':first.st_ino,'uid_map_hex':raw.hex()}}

def _observe():
    before=time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    utc=datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    boot=_read('/proc/sys/kernel/random/boot_id',64).decode('ascii').strip()
    require(re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot),'NAMESPACE_BOOT_ID')
    domain={'boot_id':boot,'time_namespace_inode':os.stat('/proc/self/ns/time').st_ino,'clock_id':'CLOCK_BOOTTIME'}
    after=time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    require(0<=after-before<=1_000_000_000,'NAMESPACE_CLOCK_UNCERTAINTY')
    return domain,{'utc':utc,'boottime_ns':after}

def _utc(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z',value),
            'NAMESPACE_STAMP_FORMAT')
    return datetime.fromisoformat(value.replace('Z','+00:00'))

def _identity(value):
    require(type(value) is dict and set(value)=={'pid','start_ticks','uid'}
            and all(type(value[k]) is int for k in value)
            and value['pid']>0 and value['start_ticks']>0 and value['uid']>=0,
            'NAMESPACE_PROCESS_SELECTION')
    return dict(value)

def observe_host_user_namespace(*, subject, supervisor, clock_domain, clock_anchor_stamp):
    """Observe; never accept supplied namespace objects or success labels."""
    require(sys.platform=='linux' and os.getuid()==os.geteuid()==0,'ROOT_NAMESPACE_OBSERVER_REQUIRED')
    subject=_identity(subject);supervisor=_identity(supervisor)
    require(subject['uid']>0 and supervisor['uid']==0
            and supervisor==_process(os.getpid()),'SELECTED_NAMESPACE_PROCESSES')
    require(type(clock_domain) is dict and set(clock_domain)=={'boot_id','time_namespace_inode','clock_id'}
            and clock_domain['clock_id']=='CLOCK_BOOTTIME'
            and type(clock_domain['time_namespace_inode']) is int and clock_domain['time_namespace_inode']>0,
            'NAMESPACE_CLOCK_DOMAIN')
    require(type(clock_anchor_stamp) is dict and set(clock_anchor_stamp)=={'utc','boottime_ns'}
            and type(clock_anchor_stamp['boottime_ns']) is int and clock_anchor_stamp['boottime_ns']>=0,
            'NAMESPACE_CLOCK_ANCHOR')
    domain,start=_observe()
    require(domain==clock_domain and clock_anchor_stamp['boottime_ns']<=start['boottime_ns']
            and _utc(clock_anchor_stamp['utc'])<=_utc(start['utc']), 'NAMESPACE_ORIGINAL_CLOCK')
    identities={'host_init':1,'supervisor':supervisor['pid'],'subject':subject['pid']}
    first={label:_row(pid) for label,pid in identities.items()}
    require(first['host_init']['process']['pid']==1 and first['host_init']['process']['uid']==0
            and first['supervisor']['process']==supervisor
            and first['subject']['process']==subject,'NAMESPACE_PROCESS_BINDING')
    require(first['host_init']['state']==first['supervisor']['state']==first['subject']['state'],
            'NAMESPACE_HOST_IDENTITY_MISMATCH')
    second={label:_row(pid) for label,pid in identities.items()}
    finish_domain,finish=_observe()
    require(second==first and finish_domain==domain
            and 0<=finish['boottime_ns']-start['boottime_ns']<=1_000_000_000
            and _utc(start['utc'])<=_utc(finish['utc']), 'NAMESPACE_OBSERVATION_CHANGED')
    return {'format':'forex.source-test-host-user-namespace/1','boot_id':domain['boot_id'],
            'observed_at_utc':finish['utc'],**first}

