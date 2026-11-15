"""Public test-only child. Runs only in a separately approved Linux test run."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import struct
import time


def main():
    parser=argparse.ArgumentParser()
    for flag in ('discovery-fd','release-fd','group','inventory-sha256','marker'):
        parser.add_argument('--'+flag,required=True)
    args=parser.parse_args()
    discovery=int(args.discovery_fd);release=int(args.release_fd)
    for fd in (discovery,release):
        if not fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_NONBLOCK:
            raise RuntimeError('inherited child pipe is blocking')
    def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    body=canonical({'format':'forex.test-driver-discovery/1','group_id':args.group,
        'inventory_sha256':args.inventory_sha256,'test_ids':['public.Case.test_actual']})
    wire=struct.pack('!I',len(body))+body
    deadline=time.monotonic()+20
    offset=0
    while offset<len(wire):
        if time.monotonic()>=deadline:raise RuntimeError('public child write timeout')
        if not select.select([],[discovery],[],0.05)[1]:continue
        try:offset+=os.write(discovery,wire[offset:])
        except BlockingIOError:continue
    os.close(discovery)
    received=bytearray()
    while True:
        if time.monotonic()>=deadline:raise RuntimeError('public child release timeout')
        if not select.select([release],[],[],0.05)[0]:continue
        try:block=os.read(release,65536)
        except BlockingIOError:continue
        if not block:break
        received.extend(block)
        if len(received)>524292:raise RuntimeError('release overflow')
    os.close(release)
    if len(received)<4 or struct.unpack('!I',received[:4])[0]!=len(received)-4:
        raise RuntimeError('release frame size')
    expected=canonical({'format':'forex.test-driver-start/1','group_id':args.group,
        'discovery_sha256':hashlib.sha256(body).hexdigest()})
    if bytes(received[4:])!=expected:raise RuntimeError('release binding')
    Path(args.marker).write_bytes(b'EXECUTED_AFTER_RELEASE')
    os.write(1,b'EXECUTED_AFTER_RELEASE\n')


if __name__=='__main__':main()
