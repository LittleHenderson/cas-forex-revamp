"""Standard-library gates for a separately approved B guest; import is inert.

The root-owned, read-only configuration and receipt pins are supplied by the
independent infrastructure controller. Payload labels cannot appoint that trust
root. This source neither provisions nor establishes cloud approval itself.
"""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys
import platform
import time
from model_state_directory import observe_state_directory

MODE = 'STAGE_B_ONLY'
PHASES = {'probe': (2, 1024, 256, 60, 600), 'acceptance': (30, 4096, 512, 120, 5400)}


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def utc(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    need(parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0, 'UTC timestamp required')
    return parsed


def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, 'duplicate JSON member')
        value[key] = item
    return value


def load(raw):
    def reject(value):
        raise RuntimeError('nonfinite JSON value')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=reject)


def file_hash(path):
    h = sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def regular(path, root, *, readonly=False, root_owned=False):
    path, root = Path(path), Path(root)
    need(path.is_absolute() and path.is_relative_to(root) and '..' not in path.parts, 'unconfined guest file')
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        need(not current.is_symlink(), 'symlink guest input')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'materialized single-link regular input required')
    if readonly:
        need(os.statvfs(path).f_flag & os.ST_RDONLY, 'frozen guest input is not on a read-only mount')
    if root_owned:
        need(info.st_uid == 0 and info.st_mode & 0o022 == 0, 'controller input ownership differs')
    return path


def read_record(row, root, *, readonly=True, maximum=4194304):
    path = regular(row['path'], root, readonly=readonly, root_owned=True)
    need(type(row['bytes']) is int and 0 < row['bytes'] <= maximum and path.stat().st_size == row['bytes'], 'receipt size differs')
    raw = path.read_bytes()
    need(sha256(raw).hexdigest() == row['sha256'], 'controller-pinned receipt differs')
    return load(raw)


def config_contract(cfg, *, now):
    """Pure configuration checks, independently testable without Linux/services."""
    need(cfg.get('schema') == 'forex.stage-b-guest/1' and cfg.get('execution_mode') == MODE, 'separate B configuration required')
    need(type(cfg.get('run_id')) is str and re.fullmatch(r'fx-b-[a-f0-9]{16}', cfg['run_id']), 'new B-only execution identity required')
    need(cfg.get('model_launch_allowed') is True and type(cfg.get('model_inference_calls_limit')) is int
         and cfg['model_inference_calls_limit'] == 32 and type(cfg.get('u1_inference_calls_limit')) is int
         and cfg.get('u1_inference_calls_limit') == 0,
         'exact total 32: two probes plus 30 mandatory first calls; no retry/U1 allocation')
    base = '/opt/cas-forex/' + cfg['run_id']
    need(cfg.get('source_directory') == base + '/source' and cfg.get('models_directory') == base + '/models'
         and cfg.get('state_directory') == '/var/lib/cas-forex-' + cfg['run_id'], 'fixed B path geometry required')
    t0, end = utc(cfg['t0_utc']), utc(cfg['work_deadline_utc'])
    bootstrap, test_end = utc(cfg['bootstrap_started_utc']), utc(cfg['test_deadline_utc'])
    need((end-t0).total_seconds() == 13200 and t0 <= bootstrap < test_end <= end
         and (test_end-bootstrap).total_seconds() <= 7200 and t0 <= now < end,
         'original shared bootstrap/test and absolute B deadlines required')
    need(type(cfg.get('seed')) is int and 0 <= cfg['seed'] <= 2147483647, 'explicit fixed seed required')
    need(type(cfg.get('files')) is list and cfg['files'], 'complete frozen file inventory missing')
    paths = [r['path'] for r in cfg['files']]
    need(len(paths) == len(set(paths)), 'duplicate frozen file')
    need(type(cfg.get('role_files')) is list and len(cfg['role_files']) == 8, 'all eight runtime/model roles required')
    isolation=cfg.get('isolation')
    need(type(isolation) is dict and set(isolation)=={'channel_id','issuer_binding_sha256','observer_binding_sha256',
         'authority_path','release_path','probe_paths','boot_id'}, 'exact independent isolation configuration required')
    need(type(isolation['channel_id']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}',isolation['channel_id']),
         'selected current channel required')
    for key in ('issuer_binding_sha256','observer_binding_sha256'):
        need(type(isolation[key]) is str and re.fullmatch('[0-9a-f]{64}',isolation[key]),'selected external identity pin missing')
    from uuid import UUID
    need(type(isolation['boot_id']) is str and str(UUID(isolation['boot_id']))==isolation['boot_id'],'external boot UUID required')
    need(type(isolation['probe_paths']) is list and 5<=len(isolation['probe_paths'])<=32
         and len(set(isolation['probe_paths']))==len(isolation['probe_paths']),'bounded actual-target probe inventory required')
    for target in [isolation['authority_path'],isolation['release_path'],*isolation['probe_paths']]:
        need(type(target) is str and Path(target).is_absolute() and Path(target).is_relative_to(base)
             and '..' not in Path(target).parts,'external isolation path outside run')
    need(isolation['authority_path']!=isolation['release_path'],'authority and release must be separate records')
    return Path(base), end, test_end


def observe_isolation(cfg):
    need(os.geteuid() != 0 and set(os.listdir('/sys/class/net')) == {'lo'}, 'unprivileged loopback-only namespace required')
    status = Path('/proc/self/status').read_text()
    need('NoNewPrivs:\t1' in status, 'NoNewPrivileges missing')
    for name in ('CapEff:', 'CapPrm:', 'CapAmb:', 'CapBnd:'):
        lines = [line for line in status.splitlines() if line.startswith(name)]
        need(len(lines) == 1 and int(lines[0].split()[1], 16) == 0, 'workload capabilities remain')
    for path in ('/root', '/home'):
        try:
            os.listdir(path)
        except PermissionError:
            pass
        else:
            raise RuntimeError('host path is not hidden')
    need(not any(k.startswith(('AWS_', 'AZURE_', 'GOOGLE_')) or k.upper().endswith('_PROXY') for k in os.environ), 'cloud/proxy environment leaked')
    state_observation = observe_state_directory(cfg)
    return dict(observed_utc=datetime.now(timezone.utc).isoformat(), run_id=cfg['run_id'], uid=os.geteuid(),
                interfaces=['lo'], capabilities=0, host_paths_inaccessible=True,
                state_directory=state_observation, deadline_utc=cfg['work_deadline_utc'])


def verify_sources(cfg, base, *, readonly=True):
    """No archive label substitutes for exact read-only staged bytes."""
    for row in cfg['files']:
        path = regular(row['path'], base, readonly=readonly, root_owned=True)
        need(type(row['bytes']) is int and path.stat().st_size == row['bytes'] and file_hash(path) == row['sha256'], 'staged file identity differs')
    by_path = {r['path']: r for r in cfg['files']}
    manifest = read_record(cfg['evidence']['source_manifest'], base, readonly=readonly)
    need(cfg['evidence']['source_manifest']['sha256'] == cfg['source_manifest_sha256'], 'source manifest pin differs')
    manifest_rows = {str(Path(cfg['source_directory'])/r['path']): r for r in manifest['files']}
    actual_source = {p for p in by_path if Path(p).is_relative_to(cfg['source_directory'])}
    need(actual_source == set(manifest_rows), 'source file inventory differs from accepted freeze')
    for path, row in manifest_rows.items():
        need(by_path[path]['bytes'] == row['bytes'] and by_path[path]['sha256'] == row['sha256'], 'source manifest member differs')
    assets = read_record(cfg['evidence']['asset_manifest'], base, readonly=readonly)
    need(cfg['evidence']['asset_manifest']['sha256'] == cfg['asset_manifest_sha256']
         and assets.get('runtime_lock_sha256') == 'a443ba9559652ccdecbfa2f75d624fa3fcf7802a6b34e31038b41080ffa0c02a', 'approved full runtime extraction pin unavailable')
    asset_rows = {r['path']: r for r in assets['files']}
    need({p for p in by_path if p not in actual_source} == set(asset_rows)
         and all(by_path[p] == row for p, row in asset_rows.items()), 'complete runtime/model inventory differs')
    for role in cfg['role_files']:
        need(by_path.get(role['path']) == {k: role[k] for k in ('path', 'bytes', 'sha256')}, 'runtime role absent from complete inventory')
    for field in ('node_binary', 'ollama_binary', 'runner_binary'):
        need(cfg[field] in by_path, 'explicit executable missing from inventory')
    for folder in (cfg['source_directory'], str(base/'runtime'), cfg['models_directory']):
        for path in Path(folder).rglob('*'):
            need(not path.is_symlink(), 'unexpected staged symlink')
            if path.is_file():
                need(str(path) in by_path, 'unlisted source/runtime/model file')
    return by_path


def verify_python(cfg, *, readonly=True):
    row = cfg['python_runtime']
    executable = regular(row['path'], Path('/usr/bin'), readonly=readonly, root_owned=True)
    need(executable == Path(sys.executable).resolve() and cfg['python_version'] == platform.python_version()
         and sys.version_info[:2] == (3, 12) and executable.stat().st_size == row['bytes']
         and file_hash(executable) == row['sha256'], 'pinned AMI Python runtime differs')


def verify_controller_evidence(cfg, base, *, readonly=True):
    evidence = cfg['evidence']
    # Do not expose sealed case contents during controller verification. Hashes
    # are checked only after a durable bundle-exposure intent is retained.
    sealed_names = {'suite', 'keys', 'schedules', 'counterparts', 'predicates'}
    receipts = {name: read_record(row, base, readonly=readonly) for name, row in evidence.items() if name not in sealed_names}
    auth = receipts['authorization']
    need(auth.get('execution_mode') == MODE and auth.get('run_id') == cfg['run_id']
         and auth.get('source_manifest_sha256') == cfg['source_manifest_sha256']
         and auth.get('asset_manifest_sha256') == cfg['asset_manifest_sha256']
         and auth.get('t0_utc') == cfg['t0_utc'] and auth.get('work_deadline_utc') == cfg['work_deadline_utc']
         and auth.get('instance_id') == cfg['instance_id'] and auth.get('security_group_id') == cfg['security_group_id']
         and auth.get('automation_execution_id') == cfg['automation_execution_id']
         and auth.get('no_overlap_verified') is True and auth.get('approved') is True,
         'separate exact B controller authorization unavailable')
    need(auth.get('pilot_spending_limit_usd') == '15.00'
         and auth.get('pilot_spending_period') == 'FIRST_30_DAYS_BEFORE_TAX'
         and auth.get('shared_pilot_spend_receipt_sha256')
         and auth.get('incremental_route_cost_fits_remaining_pilot_budget') is True,
         'shared first-30-days pilot budget review unavailable; B is not a fresh $15 allocation')
    need(auth.get('suite_sha256') == evidence['suite']['sha256'] and auth.get('keys_sha256') == evidence['keys']['sha256'],
         'sealed acceptance files not bound by controller approval')
    need(auth.get('custody_sha256') == {name: evidence[name]['sha256'] for name in sorted(sealed_names)}
         and auth.get('model_inference_calls_limit') == 32 and auth.get('model_window_seconds') == 5400,
         'complete custody and shared model budget binding missing')
    source_review = receipts['source_review']
    need(source_review.get('source_manifest_sha256') == cfg['source_manifest_sha256']
         and source_review.get('status') == 'ACCEPTED_SOURCE_ONLY'
         and source_review.get('independent_reviewer_id'), 'independent final source review missing')
    proof = receipts['stop_proof']
    execution = proof.get('execution', {})
    steps = [s for s in execution.get('StepExecutions', []) if s.get('StepName') == 'proofStop']
    need(execution.get('AutomationExecutionId') == cfg['automation_execution_id']
         and execution.get('CurrentStepName') == 'waitExpiry' and execution.get('AutomationExecutionStatus') == 'InProgress'
         and proof.get('independent_ec2_state') == 'stopped' and len(steps) == 1 and steps[0].get('StepStatus') == 'Success',
         'independent stop observation unavailable')
    for key, expected in {'InstanceId': cfg['instance_id'], 'ObservedState': 'stopped', 'WasRunning': 'true', 'StopRequested': 'true'}.items():
        need([str(x).lower() for x in steps[0]['Outputs'].get(key, [])] == [expected.lower()], 'stop observation does not bind this instance')
    sealed = receipts['egress']
    need(sealed.get('group_id') == cfg['security_group_id'] and sealed.get('outbound_rules') == [], 'observed cloud egress seal unavailable')
    a = receipts['stage_a_acceptance']
    need(a.get('source_archive_sha256') == '31567c54ab9bf32d14c3c8b1981d91b24427fd77e0cf8ce2323a4c43da58283b'
         and a.get('status') == 'PASS' and a.get('inference_calls') == 0
         and a.get('continuous_a') == 'PASS' and a.get('g4') == 'PASS' and a.get('receipt_manifest_sha256'),
         'independently accepted Stage A runtime evidence missing')
    return auth


class PhaseGate:
    def __init__(self, cfg, phase, *, clock, monotonic=time.monotonic, shared_window=None):
        need(phase in PHASES, 'unknown inference phase')
        self.cfg, self.phase, self.clock, self.monotonic = cfg, phase, clock, monotonic
        self.started, self.tick = clock(), monotonic()
        self.end = min(utc(cfg['work_deadline_utc']), self.started + timedelta(seconds=PHASES[phase][4]))
        self.shared_window = shared_window
        if shared_window is not None:
            shared_window.require_remaining(0)
            self.end = min(self.end, shared_window.end)

    def __call__(self, invocation):
        caps = PHASES[self.phase]
        if self.shared_window is not None:
            self.shared_window.require_remaining(caps[3])
        budget = invocation.budget
        actual = (budget.max_calls, budget.max_input_tokens_per_call, budget.max_generated_tokens_per_call,
                  budget.max_seconds_per_call, budget.max_total_seconds)
        now = self.clock()
        need(actual == caps and self.started <= now and now+timedelta(seconds=caps[3]) <= self.end
             and self.monotonic()-self.tick+caps[3] <= caps[4], 'phase budget or deadline differs')
        need(invocation.model.model_id == 'qwen3:0.6b' and invocation.model.reasoning_effort == 'disabled'
             and invocation.seed == self.cfg['seed'], 'model/settings differ from bounded route')
