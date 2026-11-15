"""Source-test deployment caller. Import is inert; main is explicit execution.

The separately reviewed outer launcher must select this source, configuration
and an OS-authenticated one-invocation approval. This file creates no approval,
role service, key, directory, supervisor or replacement time allowance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import threading

MAX_CONFIG = 4 * 1024 * 1024
MAX_MANIFEST = 8 * 1024 * 1024
MAX_SOURCE_FILE = 16 * 1024 * 1024
HASH = re.compile(r'[0-9a-f]{64}\Z')
IMPORT_ROOTS = ('src', 'shared-interface', 'operational/authority/source',
                'operational/measurement/source', 'operational/custody/source')
CONFIG_FIELDS = {'format', 'execution_mode', 'model_launch_allowed',
    'model_inference_calls_limit', 'stage_b_status', 'source_directory',
    'source_manifest', 'completion_material', 'completion_selection',
    'original_clock', 'custody_config', 'public_keys', 'selection_use',
    'clock_domain', 'clock_anchor_stamp', 'work_started_utc', 'work_deadline_utc',
    'environment', 'environment_profile_sha256', 'parser_component_sha256',
    'parser_schema_sha256', 'capture_directory', 'approval_path', 'attempt_directory'}


class BootstrapUnavailable(RuntimeError): pass


def require(condition, reason):
    if not condition: raise BootstrapUnavailable(reason)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def decode(raw, *, canonical_required=True):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'DUPLICATE_JSON_KEY')
            value[key] = item
        return value
    def reject(value): raise BootstrapUnavailable('NONINTEGER_JSON_NUMBER')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_float=reject, parse_constant=reject)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise BootstrapUnavailable('INVALID_JSON') from error
    require(not canonical_required or canonical(value) == raw, 'NONCANONICAL_JSON')
    return value


def absolute(path):
    require(type(path) is str and path.startswith('/') and '\\' not in path
            and '\x00' not in path and str(PurePosixPath(path)) == path
            and all(part not in ('.', '..') for part in PurePosixPath(path).parts),
            'ABSOLUTE_POSIX_PATH')
    return path


def relative(path):
    require(type(path) is str and path and not path.startswith('/')
            and '\\' not in path and '\x00' not in path
            and str(PurePosixPath(path)) == path
            and all(part not in ('.', '..') for part in PurePosixPath(path).parts),
            'SAFE_SOURCE_MEMBER')
    parts = PurePosixPath(path).parts
    require(not any(part.lower() in {'.aws', '.git', '.codex', '.private', 'stage-b-sealed'}
                    or part.lower().startswith('.env') for part in parts)
            and PurePosixPath(path).suffix.lower() not in {'.key', '.pem', '.pfx', '.p12'},
            'EXCLUDED_SOURCE_CONTENT')
    return path


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def protected_read(path, *, maximum, expected=None):
    """Walk every component with no-follow; root-controlled readable data only."""
    absolute(path)
    require(sys.platform == 'linux', 'LINUX_REQUIRED')
    parts = PurePosixPath(path).parts[1:]
    require(parts, 'REGULAR_FILE_REQUIRED')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory)
            try:
                st = os.fstat(child)
                require(st.st_uid == 0 and not st.st_mode & 0o022, 'UNPROTECTED_PARENT')
            except BaseException:
                os.close(child)
                raise
            os.close(directory); directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_uid == 0 and not before.st_mode & 0o022
                    and 0 < before.st_size <= maximum, 'UNPROTECTED_OR_OVERSIZE_FILE')
            if expected is not None: require(_identity(before) == expected, 'FILE_REPLACED')
            chunks = []; total = 0
            while True:
                piece = os.read(fd, min(65536, maximum + 1 - total))
                if not piece: break
                chunks.append(piece); total += len(piece)
                require(total <= maximum, 'FILE_SIZE_LIMIT')
            raw = b''.join(chunks)
            require(len(raw) == before.st_size and _identity(os.fstat(fd)) == _identity(before)
                    and _identity(os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)) == _identity(before),
                    'FILE_CHANGED_DURING_READ')
            return raw, _identity(before)
        finally: os.close(fd)
    finally: os.close(directory)


def pinned_file(row, *, maximum):
    require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
            and type(row['bytes']) is int and 0 < row['bytes'] <= maximum
            and type(row['sha256']) is str and HASH.fullmatch(row['sha256']),
            'FILE_PIN_FIELDS')
    raw, identity = protected_read(row['path'], maximum=maximum)
    require(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'FILE_PIN_MISMATCH')
    return raw, identity


def validate_config(config):
    require(type(config) is dict and set(config) == CONFIG_FIELDS, 'CONFIG_FIELDS')
    require(config['format'] == 'forex.source-test-bootstrap/1'
            and config['execution_mode'] == 'STAGE_A_ONLY'
            and config['model_launch_allowed'] is False
            and type(config['model_inference_calls_limit']) is int
            and config['model_inference_calls_limit'] == 0
            and config['stage_b_status'] == 'BLOCKED', 'SOURCE_ONLY_GUARDS')
    for field in ('source_directory', 'capture_directory', 'approval_path'): absolute(config[field])
    attempt = config['attempt_directory']
    require(type(attempt) is dict and set(attempt) == {'path', 'device', 'inode', 'uid', 'gid', 'mode'},
            'ATTEMPT_DIRECTORY_FIELDS')
    absolute(attempt['path'])
    require(all(type(attempt[k]) is int and attempt[k] >= 0
                for k in ('device', 'inode', 'uid', 'gid', 'mode'))
            and attempt['mode'] == 0o700, 'ATTEMPT_DIRECTORY_PIN')
    for field in ('environment_profile_sha256', 'parser_component_sha256'):
        require(type(config[field]) is str and HASH.fullmatch(config[field]), 'CONFIG_HASH')
    parser_schemas = config['parser_schema_sha256']
    require(type(parser_schemas) is dict and set(parser_schemas) == {
        'forex.python-framework-report/2', 'forex.node-tap-report/1',
        'forex.node-version-report/1'}, 'PARSER_SCHEMA_FORMATS')
    require(all(type(value) is str and HASH.fullmatch(value)
                for value in parser_schemas.values()), 'PARSER_SCHEMA_HASH')
    environment = config['environment']
    require(type(environment) is dict and all(type(k) is str and type(v) is str
            for k, v in environment.items()), 'EXACT_CHILD_ENVIRONMENT')
    allowed = {'PATH', 'LANG', 'LC_ALL', 'TZ', 'HOME', 'TMPDIR', 'LD_LIBRARY_PATH'}
    require(set(environment) <= allowed and sha(canonical(environment)) ==
            config['environment_profile_sha256'], 'ENVIRONMENT_PROFILE')
    keys = config['public_keys']
    require(type(keys) is dict and 0 < len(keys) <= 128, 'PUBLIC_KEY_MAP')
    for key, value in keys.items():
        require(type(key) is str and HASH.fullmatch(key) and type(value) is str
                and re.fullmatch('[0-9a-f]{64}', value) and sha(bytes.fromhex(value)) == key,
                'PUBLIC_KEY_PIN')
    return config


def verify_source(root, manifest):
    """Exact regular-file allowlist including this caller; never execute a file."""
    absolute(root)
    require(type(manifest) is dict and type(manifest.get('files')) is list
            and 0 < len(manifest['files']) <= 4096, 'SOURCE_MANIFEST')
    selected = {}
    for row in manifest['files']:
        require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'SOURCE_ROW')
        name = relative(row['path'])
        require(name not in selected and type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_SOURCE_FILE
                and type(row['sha256']) is str and HASH.fullmatch(row['sha256']), 'SOURCE_ROW_PIN')
        # Empty package files are permitted, unlike approval/config objects.
        path = root + '/' + name
        if row['bytes'] == 0:
            info = os.lstat(path)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
                    and not info.st_mode & 0o022 and info.st_size == 0, 'EMPTY_SOURCE_FILE')
            # Walk parents by reading a pinned nonempty sibling is not sufficient.
            parent = PurePosixPath(path).parent
            for directory in [parent, *parent.parents]:
                st = os.lstat(directory)
                require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                        'SOURCE_PARENT')
            raw = b''
        else: raw, unused = protected_read(path, maximum=MAX_SOURCE_FILE)
        require(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'SOURCE_BYTES_CHANGED')
        selected[name] = row
    observed = set()
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            require(not os.path.islink(os.path.join(directory, name)), 'SOURCE_DIRECTORY_SYMLINK')
        for name in names:
            observed.add(Path(directory, name).relative_to(root).as_posix())
    require(observed == set(selected), 'SOURCE_ALLOWLIST_MEMBERSHIP')
    return selected


def process_identity(pid):
    require(type(pid) is int and pid > 0, 'PROCESS_ID')
    raw = Path(f'/proc/{pid}/stat').read_bytes()
    tail = raw[raw.rfind(b')') + 2:].split()
    require(len(tail) >= 20 and tail[0] not in (b'Z', b'X'), 'PROCESS_NOT_LIVE')
    return {'pid': pid, 'start_ticks': int(tail[19]),
            'uid': os.stat(f'/proc/{pid}').st_uid}


def _bounded_proc_bytes(path, maximum):
    with open(path, 'rb', buffering=0) as stream:
        chunks = []; total = 0
        while True:
            piece = stream.read(maximum + 1 - total)
            if not piece: break
            chunks.append(piece); total += len(piece)
            require(total <= maximum, 'PROC_OBSERVATION_BOUND')
        raw = b''.join(chunks)
    require(0 < len(raw) <= maximum, 'PROC_OBSERVATION_BOUND')
    return raw


def _namespace_state(namespace_path, uid_map_path):
    before = os.stat(namespace_path)
    raw = _bounded_proc_bytes(uid_map_path, 256)
    after = os.stat(namespace_path)
    require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
            'CURRENT_USER_NAMESPACE_CHANGED')
    require(raw.split() == [b'0', b'0', b'4294967295'],
            'HOST_UID_AUTHORITY_UNAVAILABLE')
    return {'device': before.st_dev, 'inode': before.st_ino, 'uid_map_hex': raw.hex()}


def observe_current_user_namespace():
    """Fresh calling-thread observation only; this is not authority by itself."""
    require(sys.platform == 'linux', 'LINUX_REQUIRED')
    subject = process_identity(os.getpid())
    require(subject['uid'] == os.getuid() == os.geteuid() and subject['uid'] > 0,
            'EXACT_NONROOT_UID')
    thread_id = threading.get_native_id()
    state = _namespace_state('/proc/thread-self/ns/user', '/proc/thread-self/uid_map')
    boot = _bounded_proc_bytes('/proc/sys/kernel/random/boot_id', 64).decode('ascii').strip()
    require(re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot),
            'BOOT_ID_SHAPE')
    require(process_identity(os.getpid()) == subject
            and threading.get_native_id() == thread_id, 'CURRENT_PROCESS_CHANGED')
    return {'subject': subject, 'thread_id': thread_id, 'boot_id': boot, 'state': state}


def require_initial_user_namespace(proof, *, receipt, observed):
    """Consume an exact root-receipt proof plus fresh local kernel observation.

    Caller must authenticate the containing protected receipt first. This pure
    comparison never creates authority, reads another user's namespace, or
    grants a capability. Root producer observations are versioned separately.
    """
    require(type(proof) is dict and set(proof) == {
        'format', 'boot_id', 'observed_at_utc', 'host_init', 'supervisor', 'subject'}
        and proof['format'] == 'forex.source-test-host-user-namespace/1',
        'HOST_NAMESPACE_PROOF_SHAPE')
    require(proof['boot_id'] == observed['boot_id'] == receipt['clock_domain']['boot_id']
            and proof['observed_at_utc'] == receipt['observed_at_utc'],
            'HOST_NAMESPACE_PROOF_SCOPE')
    rows = []
    for label in ('host_init', 'supervisor', 'subject'):
        row = proof[label]
        require(type(row) is dict and set(row) == {'process', 'state'},
                'HOST_NAMESPACE_OBSERVATION_SHAPE')
        process, state = row['process'], row['state']
        require(type(process) is dict and set(process) == {'pid', 'start_ticks', 'uid'}
                and all(type(process[k]) is int for k in process)
                and process['pid'] > 0 and process['start_ticks'] > 0 and process['uid'] >= 0,
                'HOST_NAMESPACE_PROCESS_SHAPE')
        require(type(state) is dict and set(state) == {'device', 'inode', 'uid_map_hex'}
                and type(state['device']) is int and state['device'] >= 0
                and type(state['inode']) is int and state['inode'] > 0
                and type(state['uid_map_hex']) is str
                and re.fullmatch('([0-9a-f]{2}){1,256}', state['uid_map_hex']),
                'HOST_NAMESPACE_STATE_SHAPE')
        raw_map = bytes.fromhex(state['uid_map_hex'])
        require(raw_map.split() == [b'0', b'0', b'4294967295'],
                'HOST_UID_AUTHORITY_UNAVAILABLE')
        rows.append(row)
    require(rows[0]['process']['pid'] == 1 and rows[0]['process']['uid'] == 0
            and rows[1]['process'] == receipt['supervisor']
            and rows[1]['process']['uid'] == 0
            and rows[2]['process'] == receipt['subject'] == observed['subject']
            and rows[2]['process']['uid'] > 0, 'HOST_NAMESPACE_PROCESS_BINDING')
    require(rows[0]['state'] == rows[1]['state'] == rows[2]['state'] == observed['state'],
            'HOST_NAMESPACE_IDENTITY_MISMATCH')


class RootSelectedExecutionGate:
    """Proposed OS-authenticated launcher boundary, not a signing authority.

    The approved root supervisor creates the exact receipt for this process.
    The caller cannot create it, extend it, or use another process's receipt.
    Replacing/removing it withdraws permission. Infrastructure must separately
    review and supply that producer before this route is deployable.
    """
    def __init__(self, *, config_raw, config_identity, config_path, config,
                 source_manifest_raw, original_clock_raw, clock):
        self.config_raw, self.config_identity = config_raw, config_identity
        require(canonical(config) == config_raw, 'CONFIG_CONSTRUCTOR_BYTES')
        self.config_path, self.config = config_path, decode(config_raw)
        self.manifest_raw, self.original_raw = source_manifest_raw, original_clock_raw
        self.clock = clock; self.lock = threading.Lock()
        self.receipt_raw = None; self.receipt_identity = None; self.failed = False
    def __call__(self):
        if not self.lock.acquire(blocking=False):
            self.failed = True
            raise BootstrapUnavailable('EXECUTION_GATE_CONTENTION')
        try:
            require(not self.failed, 'EXECUTION_GATE_TERMINAL')
            namespace_before = observe_current_user_namespace()
            actual, unused = protected_read(self.config_path, maximum=MAX_CONFIG,
                                           expected=self.config_identity)
            require(actual == self.config_raw, 'EXECUTION_CONFIG_REPLACED')
            raw, identity = protected_read(self.config['approval_path'], maximum=32768,
                                          expected=self.receipt_identity)
            value = decode(raw)
            fields = {'format', 'decision', 'invocation_id', 'config_sha256',
                'source_manifest_sha256', 'original_clock_sha256', 'clock_domain',
                'clock_anchor_stamp', 'work_started_utc', 'work_deadline_utc',
                'subject', 'supervisor', 'observed_at_utc', 'host_user_namespace_proof'}
            require(type(value) is dict and set(value) == fields
                    and value['format'] == 'forex.source-test-launch-approval/2'
                    and value['decision'] == 'ALLOW_SOURCE_TESTS_ONCE'
                    and type(value['invocation_id']) is str
                    and re.fullmatch('[a-zA-Z0-9-]{16,128}', value['invocation_id']),
                    'EXECUTION_APPROVAL_SHAPE')
            require(value['config_sha256'] == sha(self.config_raw)
                    and value['source_manifest_sha256'] == sha(self.manifest_raw)
                    and value['original_clock_sha256'] == sha(self.original_raw), 'EXECUTION_APPROVAL_PINS')
            for key in ('clock_domain', 'clock_anchor_stamp', 'work_started_utc', 'work_deadline_utc'):
                require(value[key] == self.config[key], 'EXECUTION_APPROVAL_CLOCK')
            require(value['subject'] == process_identity(os.getpid())
                    and value['subject']['uid'] != 0, 'EXACT_APPROVED_CALLER')
            require(type(value['supervisor']) is dict and value['supervisor']['uid'] == 0
                    and value['supervisor'] == process_identity(value['supervisor']['pid']),
                    'LIVE_ROOT_SUPERVISOR')
            require_initial_user_namespace(value['host_user_namespace_proof'],
                receipt=value, observed=namespace_before)
            current = self.clock()
            from cas_forex_operational_contracts import common
            require(common.utc(self.config['clock_anchor_stamp']['utc']) <=
                    common.utc(value['observed_at_utc']) <= common.utc(current['utc']),
                    'APPROVAL_OBSERVATION_TIME')
            require(self.receipt_raw is None or self.receipt_raw == raw, 'APPROVAL_REPLACED')
            namespace_after = observe_current_user_namespace()
            require(namespace_after == namespace_before, 'CURRENT_USER_NAMESPACE_CHANGED')
            require_initial_user_namespace(value['host_user_namespace_proof'],
                receipt=value, observed=namespace_after)
            require(not self.failed, 'EXECUTION_GATE_TERMINAL')
            self.receipt_raw, self.receipt_identity = raw, identity
        except BaseException:
            self.failed = True
            raise
        finally: self.lock.release()


def claim_source_attempt(config, gate):
    """Retain one durable marker before any test; never recreate or remove it."""
    gate()
    receipt = decode(gate.receipt_raw)
    selected = config['attempt_directory']
    fd = os.open(selected['path'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require((info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
                tuple(selected[k] for k in ('device', 'inode', 'uid', 'gid', 'mode')),
                'ATTEMPT_DIRECTORY_CHANGED')
        require(info.st_uid == os.getuid() and info.st_gid == os.getgid(), 'ATTEMPT_OWNER')
        name = 'source-test-attempt-' + receipt['invocation_id'] + '.json'
        body = canonical({'format': 'forex.source-test-attempt/1',
            'invocation_id': receipt['invocation_id'], 'approval_sha256': sha(gate.receipt_raw),
            'config_sha256': sha(gate.config_raw), 'subject': receipt['subject']})
        attempt = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o600, dir_fd=fd)
        try:
            view = memoryview(body)
            while view:
                written = os.write(attempt, view); require(written > 0, 'ATTEMPT_WRITE')
                view = view[written:]
            os.fsync(attempt)
        finally: os.close(attempt)
        os.fsync(fd)
        readback = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            require(os.read(readback, len(body) + 1) == body, 'ATTEMPT_READBACK')
        finally: os.close(readback)
    finally: os.close(fd)
    gate()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args(argv)
    require(sys.platform == 'linux' and sys.version_info[:2] == (3, 12), 'PINNED_LINUX_PYTHON312')
    require(HASH.fullmatch(args.config_sha256), 'CONFIG_SHA256')
    config_raw, config_identity = protected_read(args.config, maximum=MAX_CONFIG)
    require(sha(config_raw) == args.config_sha256, 'CONFIG_PIN')
    config = validate_config(decode(config_raw))
    manifest_raw, unused = pinned_file(config['source_manifest'], maximum=MAX_MANIFEST)
    selected = verify_source(config['source_directory'], decode(manifest_raw, canonical_required=False))
    require('source_test_bootstrap.py' in selected
            and Path(__file__).absolute().as_posix() == config['source_directory'] + '/source_test_bootstrap.py',
            'EXACT_SELECTED_ENTRYPOINT')
    material, unused = pinned_file(config['completion_material'], maximum=MAX_MANIFEST)
    selection, unused = pinned_file(config['completion_selection'], maximum=MAX_CONFIG)
    original, unused = pinned_file(config['original_clock'], maximum=65536)
    for root in reversed(IMPORT_ROOTS): sys.path.insert(0, config['source_directory'] + '/' + root)
    # Only fixed modules from the fully checked tree and the pinned isolated
    # runtime are imported. No callbacks/modules/keys are loaded by arbitrary name.
    from cas_forex_operational_contracts import common
    from cas_forex_authority.authentication import LinuxOriginalClock
    from cas_forex_revamp.composition.operational_test_clock import OriginalPairedStampReader
    from cas_forex_revamp.composition.operational_source_bootstrap import build_source_bootstrap
    reader = OriginalPairedStampReader(original_clock_raw=original, expected_window_sha256=sha(original),
        work_started_utc=config['work_started_utc'], work_deadline_utc=config['work_deadline_utc'],
        clock_domain=config['clock_domain'], clock_anchor_stamp=config['clock_anchor_stamp'],
        clock=LinuxOriginalClock())
    gate = RootSelectedExecutionGate(config_raw=config_raw, config_identity=config_identity,
        config_path=args.config, config=config, source_manifest_raw=manifest_raw,
        original_clock_raw=original, clock=reader.read_stamp)
    gate()
    claim_source_attempt(config, gate)
    caller = build_source_bootstrap(config=config['custody_config'],
        public_keys={key: bytes.fromhex(value) for key, value in config['public_keys'].items()},
        base_execution_gate=gate, source_manifest_raw=manifest_raw,
        completion_material_raw=material, completion_selection_raw=selection,
        selection_use=config['selection_use'], original_clock_raw=original,
        clock_domain=config['clock_domain'], clock_anchor_stamp=config['clock_anchor_stamp'],
        capture_directory=config['capture_directory'], environment=config['environment'],
        environment_profile_sha256=config['environment_profile_sha256'],
        parser_component_sha256=config['parser_component_sha256'],
        parser_schema_sha256=config['parser_schema_sha256'],
        work_started_utc=config['work_started_utc'], work_deadline_utc=config['work_deadline_utc'])
    outcome = caller.execute()
    print(json.dumps({'status': caller.state, 'receipt_sha256': sha(outcome.receipt_raw),
                      'receipt_use': common.decode_canonical(outcome.receipt_use_raw)},
                     sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as error:
        # Do not print config, paths, key material, raw server errors or payloads.
        print(json.dumps({'status': 'INCOMPLETE', 'error_type': type(error).__name__}),
              file=sys.stderr)
        raise SystemExit(1)
