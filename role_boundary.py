"""Explicit Linux x86_64 process-local confinement. Import performs no syscall.

ABI layout is pinned to Linux v6.8 uapi/linux/landlock.h. No fallback, kernel
configuration, chmod, chown, mount, credential or host-policy operation exists.
The externally approved outer unit still supplies network/capability isolation.
"""
import ctypes
import errno
from hashlib import sha256
import os
from pathlib import Path
import platform
import stat

READ = (1 << 2) | (1 << 3)
EXEC = 1
WRITE = (1 << 1) | (1 << 4) | (1 << 5) | (1 << 7) | (1 << 8) | (1 << 14)
HANDLED = (1 << 15) - 1


def need(ok, why):
    if not ok:
        raise RuntimeError(why)


def identity(pid):
    text = Path('/proc', str(pid), 'stat').read_text()
    fields = text[text.rfind(')') + 2:].split()
    return {'pid': pid, 'parent_pid': int(fields[1]), 'start_ticks': int(fields[19])}


def role_observation(boot_id):
    import uuid
    need(str(uuid.UUID(boot_id))==boot_id,'externally observed boot identity required')
    result = identity(os.getpid())
    result.update(uid=os.geteuid(), gid=os.getegid(),
        boot_id=boot_id, boot_id_source='EXTERNAL_OBSERVER_PIN',
        namespaces={k: os.readlink('/proc/self/ns/' + k) for k in ('mnt', 'pid', 'net', 'time')},
        mountinfo_sha256=sha256(Path('/proc/self/mountinfo').read_bytes()).hexdigest(),
        exe=os.readlink('/proc/self/exe'))
    return result


def normalized_policy(policy):
    need(type(policy) is dict and set(policy) == {'read', 'execute', 'write'}, 'exact role policy required')
    result = {}
    for kind, paths in policy.items():
        need(type(paths) is list and len(paths) <= 64, 'bounded explicit path rules required')
        for text in paths:
            path = Path(text)
            need(type(text) is str and path.is_absolute() and '..' not in path.parts
                 and path.resolve() == path and path.exists(), 'canonical existing rule target required')
            need(text not in ('/', '/opt', '/var', '/var/lib', '/tmp', '/home'), 'broad role rule forbidden')
            rights = READ if kind == 'read' else READ | EXEC if kind == 'execute' else READ | WRITE
            if not path.is_dir():
                rights &= EXEC | (1 << 1) | (1 << 2) | (1 << 14)
            result[text] = result.get(text, 0) | rights
    return result


def confine(policy, *, allowed_fds, boot_id):
    """Call only in a freshly exec'd, single-threaded child before private input."""
    need(platform.system() == 'Linux' and platform.machine() == 'x86_64'
         and os.geteuid() != 0, 'unprivileged pinned Linux x86_64 role required')
    need(len(list(Path('/proc/self/task').iterdir())) == 1, 'confinement must precede threads')
    # No private descriptor can survive. close_fds at spawn is necessary too.
    expected = {0, 1, 2, *allowed_fds}
    observed = set()
    for p in Path('/proc/self/fd').iterdir():
        try:
            os.fstat(int(p.name)); observed.add(int(p.name))
        except OSError:
            continue
    need(observed <= expected, 'unexpected inherited descriptor')
    rules = normalized_policy(policy)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    class Ruleset(ctypes.Structure):
        _fields_ = [('fs', ctypes.c_uint64), ('net', ctypes.c_uint64)]
    class Beneath(ctypes.Structure):
        _pack_ = 1
        _fields_ = [('access', ctypes.c_uint64), ('parent_fd', ctypes.c_int32)]
    abi = libc.syscall(444, 0, 0, 1)
    need(abi >= 4, 'required Landlock ABI unavailable; never degrade')
    # TCP remains bounded by the existing loopback-only network namespace.
    attr = Ruleset(HANDLED, 0)
    fd = libc.syscall(444, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    need(fd >= 0, 'Landlock ruleset creation failed')
    try:
        for path, access in sorted(rules.items()):
            parent = os.open(path, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                item = Beneath(access, parent)
                need(libc.syscall(445, fd, 1, ctypes.byref(item), 0) == 0, 'Landlock rule failed')
            finally:
                os.close(parent)
        need(libc.prctl(38, 1, 0, 0, 0) == 0, 'no-new-privileges required')
        need(libc.syscall(446, fd, 0) == 0, 'role confinement failed')
    finally:
        os.close(fd)
    return {'abi': abi, 'handled_fs': HANDLED, 'rules': rules,
            'inherited_fds': sorted(observed), 'role': role_observation(boot_id)}


def open_probe(path):
    """Open without reading; EACCES/EPERM alone can represent denial.

    The independent observer must separately establish that the actual target
    exists and bind this fixed probe's role/process/receipt. This is not a grant.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as exc:
        return {'opened': False, 'errno': exc.errno,
                'denied': exc.errno in (errno.EACCES, errno.EPERM)}
    else:
        os.close(fd)
        return {'opened': True, 'errno': 0, 'denied': False}
