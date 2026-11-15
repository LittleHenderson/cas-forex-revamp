"""Source-only Linux launch primitives. No application imports or top-level work."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import stat
import time
from datetime import datetime, timezone

RUN = 'fx-20261010-8e1a63c5'
BASE = '/opt/cas-forex/' + RUN
UNIT = 'cas-forex-' + RUN
HASH = re.compile(r'[0-9a-f]{64}\Z')
REPORT_FORMATS = {'forex.python-framework-report/2', 'forex.node-tap-report/1',
                  'forex.node-version-report/1'}
BOOTSTRAP_FIELDS = {'format', 'execution_mode', 'model_launch_allowed',
    'model_inference_calls_limit', 'stage_b_status', 'source_directory',
    'source_manifest', 'completion_material', 'completion_selection', 'original_clock',
    'custody_config', 'public_keys', 'selection_use', 'clock_domain', 'clock_anchor_stamp',
    'work_started_utc', 'work_deadline_utc', 'environment', 'environment_profile_sha256',
    'parser_component_sha256', 'parser_schema_sha256', 'capture_directory',
    'approval_path', 'attempt_directory'}

def need(value, message):
    if not value:
        raise RuntimeError(message)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def decode(raw, canonical_required=True):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'Duplicate JSON key')
            result[key] = value
        return result
    def reject(value):
        raise RuntimeError('Noninteger JSON number')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                       parse_float=reject, parse_constant=reject)
    need(not canonical_required or canonical(value) == raw, 'Noncanonical JSON')
    return value

def utc(value):
    need(type(value) is str and value.endswith('Z'), 'Exact UTC timestamp required')
    parsed = datetime.fromisoformat(value[:-1] + '+00:00')
    need(parsed.utcoffset().total_seconds() == 0, 'UTC required')
    return parsed

def stamp():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

def absolute(value):
    need(type(value) is str and value.startswith('/') and '\\' not in value and '\x00' not in value
         and str(PurePosixPath(value)) == value and '..' not in PurePosixPath(value).parts,
         'Canonical absolute POSIX path required')
    return value

def under_base(value):
    absolute(value)
    need(value.startswith(BASE + '/'), 'Path must remain under the selected pilot root')
    return value

def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def protected_parent(path):
    """Return held root-controlled parent fd and leaf; never follow symlinks."""
    absolute(path)
    parts = PurePosixPath(path).parts[1:]
    need(parts, 'File leaf required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            need(info.st_uid == 0 and not info.st_mode & 0o022, 'Unprotected parent')
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise

def read_protected(path, maximum=8*1024*1024, expected=None):
    parent, leaf = protected_parent(path)
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                 and not before.st_mode & 0o022 and 0 <= before.st_size <= maximum, 'Unprotected file')
            need(expected is None or identity(before) == expected, 'Protected file replaced')
            chunks = []; total = 0
            while True:
                block = os.read(fd, min(65536, maximum + 1 - total))
                if not block: break
                chunks.append(block); total += len(block)
                need(total <= maximum, 'File bound')
            raw = b''.join(chunks)
            need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                 == identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)), 'File changed')
            return raw, identity(before)
        finally:
            os.close(fd)
    finally:
        os.close(parent)

def pinned(row, maximum=32*1024*1024):
    need(type(row) is dict and set(row) == {'path','bytes','sha256'}
         and type(row['bytes']) is int and 0 <= row['bytes'] <= maximum
         and type(row['sha256']) is str and HASH.fullmatch(row['sha256']), 'File pin shape')
    raw, info = read_protected(row['path'], maximum)
    need(len(raw) == row['bytes'] and digest(raw) == row['sha256'], 'File pin mismatch')
    return raw, info

def _set_created_receipt_mode(fd, *, uid, gid, mode):
    """Seal only a newly created, held descriptor; never repair an old path."""
    need(type(mode) is int and mode in (0o600,0o644), 'Approved receipt mode')
    before = os.fstat(fd)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == uid,
         'New receipt owner/type')
    os.fchown(fd, uid, gid)
    os.fchmod(fd, mode)
    after = os.fstat(fd)
    need(stat.S_ISREG(after.st_mode) and after.st_nlink == 1
         and (after.st_dev,after.st_ino) == (before.st_dev,before.st_ino)
         and (after.st_uid,after.st_gid,stat.S_IMODE(after.st_mode)) == (uid,gid,mode),
         'Exact receipt ownership/mode')

def create_retained(path, value, mode=0o644):
    """Exclusive root receipt creation; preserve incomplete writes on failure."""
    need(os.geteuid() == 0, 'Root receipt producer required')
    parent, leaf = protected_parent(path)
    raw = canonical(value)
    try:
        selected_gid = os.fstat(parent).st_gid
        fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view); need(count > 0, 'Uncertain receipt write')
                view = view[count:]
            # An inherited restrictive umask must not make a public startup
            # config or /2 receipt unreadable. Publish only after complete write.
            _set_created_receipt_mode(fd, uid=0, gid=selected_gid, mode=mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)
    observed, info = read_protected(path)
    need(observed == raw, 'Receipt readback differs')
    need(info[2] == 0 and info[3] == selected_gid and stat.S_IMODE(info[4]) == mode,
         'Published receipt ownership/mode differs')
    return raw, info

def process_identity(pid):
    need(type(pid) is int and pid > 0, 'Positive PID required')
    raw = Path('/proc/' + str(pid) + '/stat').read_bytes()
    tail = raw[raw.rfind(b')') + 2:].split()
    need(len(tail) >= 20 and tail[0] not in (b'Z',b'X'), 'Process not live')
    return {'pid':pid, 'start_ticks':int(tail[19]), 'uid':os.stat('/proc/'+str(pid)).st_uid}

def host_user_namespace():
    need(Path('/proc/self/uid_map').read_bytes().split() == [b'0',b'0',b'4294967295']
         and os.stat('/proc/self/ns/user').st_ino == os.stat('/proc/1/ns/user').st_ino,
         'Initial host user namespace required')

def observe_pair():
    before = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    now = stamp()
    domain = {'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'time_namespace_inode':os.stat('/proc/self/ns/time').st_ino, 'clock_id':'CLOCK_BOOTTIME'}
    after = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    need(0 <= after-before <= 1_000_000_000, 'Clock observation uncertainty')
    return domain, {'utc':now,'boottime_ns':after}

class Deadline:
    """Original UTC deadline mapped once to observed boottime; never slides."""
    def __init__(self, end, domain=None, anchor=None):
        if domain is None:
            domain, anchor = observe_pair()
        self.domain, self.anchor = domain, anchor
        self.end = utc(end)
        delta = self.end - utc(anchor['utc'])
        self.end_ns = anchor['boottime_ns'] + ((delta.days*86400+delta.seconds)*1_000_000+delta.microseconds)*1000
        self.previous = None

    def remaining(self, reserve=0):
        domain, now = observe_pair()
        need(domain == self.domain, 'Clock domain changed')
        elapsed = utc(now['utc']) - utc(self.anchor['utc'])
        elapsed_ns = ((elapsed.days*86400+elapsed.seconds)*1_000_000+elapsed.microseconds)*1000
        need(abs(elapsed_ns-(now['boottime_ns']-self.anchor['boottime_ns'])) <= 1_000_000_000,
             'Clock drift')
        if self.previous is not None:
            need(utc(now['utc']) >= utc(self.previous['utc'])
                 and now['boottime_ns'] >= self.previous['boottime_ns'], 'Clock regression')
        self.previous = now
        left = min((self.end-utc(now['utc'])).total_seconds(), (self.end_ns-now['boottime_ns'])/1e9)-reserve
        need(left > 0, 'Original deadline expired')
        return left

def read_line(fd, deadline, maximum=16384):
    data = bytearray()
    while True:
        ready, _, _ = select.select([fd], [], [], min(1.0, deadline.remaining(5)))
        if not ready: continue
        block = os.read(fd, 1)
        need(block, 'Control pipe EOF')
        if block == b'\n': return decode(bytes(data))
        data.extend(block); need(len(data) <= maximum, 'Control frame too large')

def write_line(fd, value, deadline):
    pending = memoryview(canonical(value)+b'\n')
    while pending:
        _, ready, _ = select.select([], [fd], [], min(1.0, deadline.remaining(5)))
        if not ready: continue
        count = os.write(fd, pending); need(count > 0, 'Control write uncertain')
        pending = pending[count:]

def guards(value):
    need(value.get('execution_mode') == 'STAGE_A_ONLY' and value.get('model_launch_allowed') is False
         and type(value.get('model_inference_calls_limit')) is int and value['model_inference_calls_limit'] == 0
         and value.get('stage_b_status') == 'BLOCKED', 'Zero-model guards required')

def bootstrap_shape(value):
    need(type(value) is dict and set(value) == BOOTSTRAP_FIELDS
         and value['format'] == 'forex.source-test-bootstrap/1', 'Bootstrap config shape')
    guards(value)
    mapping = value['parser_schema_sha256']
    need(type(mapping) is dict and set(mapping) == REPORT_FORMATS
         and all(type(x) is str and HASH.fullmatch(x) for x in mapping.values()),
         'Corrected three-format parser-schema mapping required')
    need(value['source_directory'] == BASE+'/source', 'Fixed source directory required')
    need(value['approval_path'] == BASE+'/receipts/source-test-launch-approval.json', 'Fixed approval path')
    return value

def bootstrap_argv(row):
    under_base(row['path'])
    need(row['path'] == BASE+'/source-test-config.json', 'Fixed bootstrap config path')
    return ['/usr/bin/python3','-I','-B',BASE+'/source/source_test_bootstrap.py',
            '--config',row['path'],'--config-sha256',row['sha256']]
