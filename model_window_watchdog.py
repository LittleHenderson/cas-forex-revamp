"""Independent Linux deadline for the exact direct-parent B driver only.

The parent is the main process of the approved KillMode=control-group systemd
unit. Killing it ends the unit and its model/browser descendants. No PID scan,
borrowed process, renewal, restart or application import is permitted.
"""
import argparse
from datetime import datetime, timezone
import math
import os
import select
import signal
import time


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--parent-pid',type=int,required=True)
    p.add_argument('--deadline-utc',required=True)
    p.add_argument('--monotonic-deadline',type=float,required=True)
    p.add_argument('--ready-fd',type=int,required=True)
    a=p.parse_args()
    deadline=datetime.fromisoformat(a.deadline_utc.replace('Z','+00:00'))
    if (os.name!='posix' or a.parent_pid!=os.getppid() or a.parent_pid<=1
            or deadline.utcoffset() is None or deadline.utcoffset().total_seconds()!=0
            or not math.isfinite(a.monotonic_deadline) or not 3<=a.ready_fd<=1024):
        raise RuntimeError('exact direct-parent UTC deadline required')
    fd=os.pidfd_open(a.parent_pid,0)
    try:
        if os.getppid()!=a.parent_pid: return 0
        poll=select.poll();poll.register(fd,select.POLLIN)
        os.write(a.ready_fd,b'R6-WINDOW-READY\n');os.close(a.ready_fd)
        while True:
            remaining=min((deadline-datetime.now(timezone.utc)).total_seconds(),a.monotonic_deadline-time.monotonic())
            if remaining<=0:
                try:signal.pidfd_send_signal(fd,signal.SIGKILL)
                except ProcessLookupError:pass
                return 1
            if poll.poll(max(1,min(1000,int(remaining*1000)))):return 0
    finally:os.close(fd)


if __name__=='__main__':raise SystemExit(main())
