"""One original-deadline child discovery/release exchange; constructor-free.

Only explicit exchange calls touch the observer-provided anonymous pipes.
No timestamp or identity supplied here is promoted to an observation.
"""
import hashlib
import json
import os
import select
import stat
import struct

MAX_BODY = 524288


def require(value, code):
    if not value: raise RuntimeError(code)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',', ':'),ensure_ascii=False,allow_nan=False).encode('utf-8')


def parse(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            require(key not in result,'DUPLICATE_DISCOVERY_KEY');result[key]=value
        return result
    value=json.loads(raw.decode('utf-8','strict'),object_pairs_hook=pairs,
        parse_constant=lambda x: (_ for _ in ()).throw(ValueError('NONFINITE_DISCOVERY')))
    require(canonical(value)==raw,'NONCANONICAL_DISCOVERY')
    return value


def discovery_body(group_id, inventory_sha256, ids):
    require(type(group_id) is str and 0<len(group_id)<=64,'DISCOVERY_GROUP')
    require(type(inventory_sha256) is str and len(inventory_sha256)==64 and
        all(c in '0123456789abcdef' for c in inventory_sha256),'DISCOVERY_PIN')
    require(type(ids) is list and all(type(x) is str and 0<len(x)<=1024 for x in ids)
        and len(ids)==len(set(ids)) and len(ids)<=100000,'DISCOVERY_IDS')
    require(bool(ids)==(group_id!='node-version'),'DISCOVERY_VERSION_MEMBERSHIP')
    raw=canonical({'format':'forex.test-driver-discovery/1','group_id':group_id,
        'inventory_sha256':inventory_sha256,'test_ids':ids})
    require(0<len(raw)<=MAX_BODY,'DISCOVERY_BODY_BOUND')
    return raw


def validate_release(raw, *, group_id, discovery_raw):
    expected={'format':'forex.test-driver-start/1','group_id':group_id,
        'discovery_sha256':hashlib.sha256(discovery_raw).hexdigest()}
    require(parse(raw)==expected,'DISCOVERY_RELEASE_MISMATCH')


def _wait(fd, *, writing, remaining):
    duration=remaining()
    require(type(duration) in (int,float) and 0<duration<=7200,'ORIGINAL_DISCOVERY_DEADLINE')
    ready=select.select([] if writing else [fd],[fd] if writing else [],[],min(duration,0.05))
    return bool(ready[1 if writing else 0])


def _write(fd, raw, remaining):
    offset=0
    while offset<len(raw):
        if not _wait(fd,writing=True,remaining=remaining):continue
        try:count=os.write(fd,raw[offset:offset+65536])
        except BlockingIOError:continue
        require(count>0,'DISCOVERY_WRITE_FAILED');offset+=count


def _read(fd, remaining):
    chunks=bytearray();size=None
    while True:
        if not _wait(fd,writing=False,remaining=remaining):continue
        try:block=os.read(fd,min(65536,MAX_BODY+5-len(chunks)))
        except BlockingIOError:continue
        if not block:break
        chunks.extend(block)
        require(len(chunks)<=MAX_BODY+4,'DISCOVERY_READ_BOUND')
        if size is None and len(chunks)>=4:
            size=struct.unpack('!I',chunks[:4])[0]
            require(0<size<=MAX_BODY,'DISCOVERY_FRAME_BOUND')
        if size is not None:require(len(chunks)<=size+4,'DISCOVERY_EXTRA_FRAME')
    require(size is not None and len(chunks)==size+4,'DISCOVERY_TRUNCATED_FRAME')
    return bytes(chunks[4:])


def exchange(*, discovery_fd, release_fd, group_id, inventory_sha256, ids, remaining):
    require(type(discovery_fd) is int and type(release_fd) is int and
        discovery_fd>=3 and release_fd>=3 and discovery_fd!=release_fd,'DISCOVERY_FDS')
    # The selected observer creates these pipes; the child accepts no path,
    # message-provided descriptor or socket rights. Verify endpoints explicitly.
    for fd in (discovery_fd,release_fd):
        require(stat.S_ISFIFO(os.fstat(fd).st_mode),'DISCOVERY_ANONYMOUS_PIPE_REQUIRED')
        require(os.readlink('/proc/self/fd/'+str(fd)).startswith('pipe:['),'DISCOVERY_NAMED_PIPE_REJECTED')
        os.set_blocking(fd,False)
    raw=discovery_body(group_id,inventory_sha256,ids)
    try:
        _write(discovery_fd,struct.pack('!I',len(raw))+raw,remaining)
    finally:
        os.close(discovery_fd)
    try:
        ack=_read(release_fd,remaining)
        validate_release(ack,group_id=group_id,discovery_raw=raw)
        require(remaining()>0,'ORIGINAL_DISCOVERY_DEADLINE')
    finally:
        os.close(release_fd)
