"""Steward-selected bounded local source-completion transport; inert on import.

No listener, root, privilege or credential is created. One request per selected
existing AF_UNIX connection. Only existing signed records establish authority.
"""
import array
import os
import socket
import stat
import struct
import time
from cas_forex_operational_contracts import common, method

REQUEST_FORMAT='forex.source-completion-local-request/1'
RESPONSE_FORMAT='forex.source-completion-local-response/1'
OPERATIONS={'CURRENT_SELECTION','READ_REGISTRATION','REGISTER_EXACT_RECORD','PUBLISH'}
ENDPOINT_FIELDS={'path','device','inode','uid','gid','mode','peer_pid','peer_uid','peer_gid',
                 'peer_start_ticks','boot_id','maximum_frame_bytes','timeout_ms','maximum_registry_entries'}
require=common.require


def closed(value, fields, code):
    require(type(value) is dict and set(value)==set(fields),code)


def endpoint_selection(value):
    closed(value,ENDPOINT_FIELDS,'ENDPOINT_SELECTION')
    common.safe_path(value['path'],absolute=True)
    require(len(os.fsencode(value['path']))<=107,'UNIX_PATH_BOUND')
    for name in ENDPOINT_FIELDS-{'path','boot_id'}:
        require(type(value[name]) is int and value[name]>=0,'ENDPOINT_INTEGER')
    require(value['peer_pid']>0 and value['peer_start_ticks']>0 and value['inode']>0
            and 0<value['maximum_frame_bytes']<=common.MAX_OBJECT
            and 0<value['timeout_ms']<=120000 and 0<value['maximum_registry_entries']<=4096
            and value['mode']<=0o777 and type(value['boot_id']) is str and 0<len(value['boot_id'])<=64,'ENDPOINT_BOUNDS')
    return common.decode_canonical(common.canonical_bytes(value))


def _read_small(path, maximum):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        raw=os.read(fd,maximum+1);require(len(raw)<=maximum,'PROCESS_OBSERVATION_BOUND')
        return raw
    finally:os.close(fd)


def peer_identity(connection, selected):
    require(os.name=='posix' and connection.family==socket.AF_UNIX
            and connection.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)==socket.SOCK_STREAM,'LOCAL_STREAM_REQUIRED')
    pid,uid,gid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
    require((pid,uid,gid)==(selected['peer_pid'],selected['peer_uid'],selected['peer_gid']),'ACTUAL_PEER_MISMATCH')
    require(_read_small('/proc/sys/kernel/random/boot_id',64).decode('ascii').strip()==selected['boot_id'],'PEER_BOOT_MISMATCH')
    raw=_read_small('/proc/'+str(pid)+'/stat',65536).decode('ascii');end=raw.rfind(')')
    require(end>0 and raw[:raw.find(' ')].isdigit() and int(raw[:raw.find(' ')])==pid,'PEER_STAT')
    fields=raw[end+2:].split()
    require(len(fields)>19 and fields[19].isdigit() and int(fields[19])==selected['peer_start_ticks'],'PEER_START_MISMATCH')


def endpoint_identity(selected):
    """No-follow parent traversal and exact selected socket metadata."""
    require(os.name=='posix','LINUX_ENDPOINT_REQUIRED')
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    fd=os.open('/',flags)
    try:
        pieces=selected['path'].split('/')[1:]
        for piece in pieces[:-1]:
            child=os.open(piece,flags,dir_fd=fd);os.close(fd);fd=child
        info=os.stat(pieces[-1],dir_fd=fd,follow_symlinks=False)
        require(stat.S_ISSOCK(info.st_mode) and (info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))
                ==tuple(selected[k] for k in ('device','inode','uid','gid','mode')),'ENDPOINT_IDENTITY')
    finally:os.close(fd)


class FrameBudget:
    def __init__(self, *, clock, deadline, timeout_ms):
        self.clock,self.deadline=clock,method.validate('Stamp',deadline).payload()
        self.local_end=time.monotonic()+timeout_ms/1000
        self.previous=None

    def remaining(self):
        now=method.validate('Stamp',self.clock()).payload();end=self.deadline
        if self.previous is not None:
            require(common.utc(now['utc'])>=common.utc(self.previous['utc']) and now['boottime_ns']>=self.previous['boottime_ns'],'TRANSPORT_CLOCK_REGRESSION')
        self.previous=now
        left=min(self.local_end-time.monotonic(),(common.utc(end['utc'])-common.utc(now['utc'])).total_seconds(),
                 (end['boottime_ns']-now['boottime_ns'])/1e9)
        require(left>0,'ORIGINAL_TRANSPORT_DEADLINE');return left


def _ancillary_reject(ancillary, flags):
    # Close every delivered descriptor before rejecting; never accept it.
    for level,kind,data in ancillary:
        if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
            fds=array.array('i');fds.frombytes(data[:len(data)-(len(data)%fds.itemsize)])
            for fd in fds:
                try:os.close(fd)
                except OSError:pass
    require(not ancillary and not flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC),'ANCILLARY_OR_TRUNCATION')


def receive_frame(connection, *, maximum, budget):
    def exact(length):
        blocks=[];remaining=length
        while remaining:
            connection.settimeout(budget.remaining())
            data,ancillary,flags,_=connection.recvmsg(min(remaining,65536),socket.CMSG_SPACE(1024),getattr(socket,'MSG_CMSG_CLOEXEC',0))
            _ancillary_reject(ancillary,flags)
            require(bool(data),'FRAME_EARLY_EOF');blocks.append(data);remaining-=len(data)
        return b''.join(blocks)
    size=struct.unpack('!I',exact(4))[0]
    require(0<size<=maximum,'FRAME_BOUND')
    raw=exact(size)
    connection.settimeout(budget.remaining())
    data,ancillary,flags,_=connection.recvmsg(1,socket.CMSG_SPACE(1024),getattr(socket,'MSG_CMSG_CLOEXEC',0))
    _ancillary_reject(ancillary,flags);require(data==b'','FRAME_TRAILING_BYTES')
    common.decode_canonical(raw,limit=maximum)
    return raw


def send_frame(connection, raw, *, maximum, budget):
    require(type(raw) is bytes and 0<len(raw)<=maximum,'FRAME_BOUND')
    common.decode_canonical(raw,limit=maximum)
    frame=struct.pack('!I',len(raw))+raw;offset=0
    while offset<len(frame):
        connection.settimeout(budget.remaining());count=connection.send(frame[offset:])
        require(count>0,'FRAME_WRITE_UNCERTAIN');offset+=count
    connection.shutdown(socket.SHUT_WR)


class LocalCompletionClient:
    def __init__(self, *, endpoint, clock, original_deadline):
        self.endpoint=endpoint_selection(endpoint);self.clock=clock
        self.deadline=method.validate('Stamp',original_deadline).raw

    def request(self, operation, payload, *, publisher_selection_sha256):
        require(operation in OPERATIONS,'LOCAL_OPERATION')
        endpoint=self.endpoint
        request={'format':REQUEST_FORMAT,'request_id':os.urandom(32).hex(),'operation':operation,
                 'publisher_selection_sha256':publisher_selection_sha256,'payload':payload}
        raw=common.canonical_bytes(request,limit=endpoint['maximum_frame_bytes'])
        budget=FrameBudget(clock=self.clock,deadline=method.decode('Stamp',self.deadline).payload(),timeout_ms=endpoint['timeout_ms'])
        endpoint_identity(endpoint)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(budget.remaining());connection.connect(endpoint['path'])
            endpoint_identity(endpoint);peer_identity(connection,endpoint)
            send_frame(connection,raw,maximum=endpoint['maximum_frame_bytes'],budget=budget)
            answer=receive_frame(connection,maximum=endpoint['maximum_frame_bytes'],budget=budget)
            peer_identity(connection,endpoint);endpoint_identity(endpoint);budget.remaining()
        response=common.decode_canonical(answer,limit=endpoint['maximum_frame_bytes'])
        closed(response,{'format','request_id','request_sha256','result'},'LOCAL_RESPONSE_SHAPE')
        require(response['format']==RESPONSE_FORMAT and response['request_id']==request['request_id']
                and response['request_sha256']==common.digest(raw),'LOCAL_RESPONSE_CORRELATION')
        return response['result']


def serve_connection(connection, *, peer, clock, original_deadline, handler):
    """One already accepted connection, never binds/listens/starts a service.

    peer is the independently selected allowed caller, using the endpoint field
    structure. Handler failures close without a fabricated successful response.
    """
    selected=endpoint_selection(peer)
    budget=FrameBudget(clock=clock,deadline=original_deadline,timeout_ms=selected['timeout_ms'])
    with connection:
        peer_identity(connection,selected)
        raw=receive_frame(connection,maximum=selected['maximum_frame_bytes'],budget=budget)
        request=common.decode_canonical(raw,limit=selected['maximum_frame_bytes'])
        closed(request,{'format','request_id','operation','publisher_selection_sha256','payload'},'LOCAL_REQUEST_SHAPE')
        require(request['format']==REQUEST_FORMAT and request['operation'] in OPERATIONS
                and type(request['request_id']) is str and len(request['request_id'])==64
                and all(c in '0123456789abcdef' for c in request['request_id']),'LOCAL_REQUEST_IDENTITY')
        peer_identity(connection,selected);budget.remaining()
        result=handler(request)
        peer_identity(connection,selected);budget.remaining()
        response={'format':RESPONSE_FORMAT,'request_id':request['request_id'],'request_sha256':common.digest(raw),'result':result}
        send_frame(connection,common.canonical_bytes(response,limit=selected['maximum_frame_bytes']),maximum=selected['maximum_frame_bytes'],budget=budget)
