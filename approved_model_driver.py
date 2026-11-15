"""Explicit B guest driver. Standard-library import is inert; no local execution.

This entrypoint requires a separately reviewed B controller/launcher route. It
cannot consume the A execution identity. No request or test runs before gates.
"""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import argparse
import json
import os
from pathlib import Path
import platform
import signal
import select
import subprocess
import sys
import time
from model_guest_boundary import (PHASES, PhaseGate, config_contract, file_hash, load, need,
    observe_isolation, read_record, regular, utc, verify_controller_evidence, verify_sources, verify_python)


def write_new(path, value):
    with path.open('x', encoding='utf-8') as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write('\n'); handle.flush(); os.fsync(handle.fileno())


def stop_group(child):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass
        if sig == signal.SIGTERM:
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
    child.wait(timeout=1)


def child_environment(cfg, out):
    # No inherited proxy/cloud/library/Python/Node injection values.
    result = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(out/'home'),
        'TMPDIR': str(out/'tmp'), 'STATE_DIRECTORY': str(out),
        'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(Path(cfg['source_directory'])/'src')}
    for name in ('home', 'tmp'):
        (out/name).mkdir(exist_ok=True)
    return result


def runtime_libraries(cfg, field):
    paths = cfg[field]
    need(type(paths) is list and paths, 'explicit verified library directories required')
    allowed = {r['path'] for r in cfg['files']}
    for text in paths:
        path = Path(text)
        need(path.is_absolute() and path.is_relative_to(Path(cfg['source_directory']).parent/'runtime')
             and path.resolve() == path and path.is_dir() and any(Path(p).parent == path for p in allowed),
             'library directory missing from exact runtime inventory')
    return ':'.join(paths)


def bounded_child(argv, *, cfg, out, name, deadline, env):
    remaining = deadline.timestamp()-time.time()-5
    need(remaining > 0, 'shared stage deadline exhausted')
    with (out/(name+'.stdout.txt')).open('xb') as stdout, (out/(name+'.stderr.txt')).open('xb') as stderr:
        child = subprocess.Popen(argv, cwd=cfg['source_directory'], env=env,
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
    try:
        return child.wait(timeout=remaining)
    finally:
        stop_group(child)


def source_tests(cfg, out, env, deadline):
    root = Path(cfg['source_directory'])
    for name in ('contracts', 'core', 'venue', 'operator', 'rpa', 'integration'):
        target = out/('tests-'+name+'.json')
        code = bounded_child(['/usr/bin/python3', '-B', str(root/'approved_test_driver.py'),
            '--test-group', name, '--output', str(target)], cfg=cfg, out=out, name='tests-'+name,
            deadline=deadline, env=env)
        report = load(target.read_bytes()) if target.is_file() else {}
        need(code == 0 and report.get('status') == 'PASS' and report.get('ran', 0) > 0
             and report.get('ran') == report.get('discovered') and report.get('skipped') == 0,
             'B source test group failed or incomplete: ' + name)
    node_env = {**env, 'LD_LIBRARY_PATH': runtime_libraries(cfg, 'node_library_directories')}
    code = bounded_child([cfg['node_binary'], '--version'], cfg=cfg, out=out, name='node-version', deadline=deadline, env=node_env)
    need(code == 0 and (out/'node-version.stdout.txt').read_text().strip() == 'v24.21.0', 'pinned Node version differs')
    tests = sorted(str(p) for p in (root/'tests/ui').glob('*.test.mjs'))
    need(tests, 'UI tests absent')
    code = bounded_child([cfg['node_binary'], '--test', *tests], cfg=cfg, out=out,
        name='tests-ui', deadline=deadline, env=node_env)
    need(code == 0, 'UI tests failed')
    write_new(out/'b-source-tests.json', {'status': 'PASS', 'finished_utc': datetime.now(timezone.utc).isoformat(),
        'original_bootstrap_started_utc': cfg['bootstrap_started_utc'], 'test_deadline_utc': cfg['test_deadline_utc']})


def probe_request(index, run_id, clock):
    # Availability only. Empty options make WAIT the sole possible selection;
    # this never counts as a strategy, management or R6 success.
    from cas_forex_revamp.contracts import (DecisionRequest, DecisionFact, EvidenceKind,
        EvidenceReference, RunScope, StateReference, content_digest)
    now = clock()
    scope = RunScope('synthetic-probe', run_id, 1, 'b-probe-1', 'no-execution', 'availability', 'none')
    state = StateReference('probe-state-'+str(index), scope, index, now, now+timedelta(seconds=120), 0)
    evidence = EvidenceReference('probe-fact-'+str(index), EvidenceKind.IMPORTED_CLAIM,
        'availability-fixture', content_digest({'index': index, 'available_actions': []}), now)
    return DecisionRequest('probe-request-'+str(index), 'probe-set-'+str(index), state, (),
        (DecisionFact('probe-'+str(index), 'Availability fixture', 'No action is supplied. WAIT is available.', (evidence.evidence_id,)),), (evidence,))


def main():
    from authority_component.release_gate import require_release_enabled
    require_release_enabled()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-config', type=Path, required=True)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    need(platform.system() == 'Linux' and sys.version_info[:2] == (3, 12), 'approved Linux Python 3.12 required')
    config_path = regular(args.guest_config, Path('/opt/cas-forex'), readonly=True, root_owned=True)
    raw = config_path.read_bytes()
    need(len(raw) <= 4194304 and sha256(raw).hexdigest() == args.config_sha256, 'exact controller config pin differs')
    cfg = load(raw)
    cfg['_verified_config_sha256'] = args.config_sha256
    clock = lambda: datetime.now(timezone.utc)
    base, deadline, test_deadline = config_contract(cfg, now=clock())
    need(Path(__file__).resolve() == Path(cfg['source_directory'])/'approved_model_driver.py', 'driver source path differs')
    isolated = observe_isolation(cfg)
    verify_python(cfg)
    verify_sources(cfg, base)
    verify_controller_evidence(cfg, base)
    out = Path(cfg['state_directory'])
    write_new(out/'b-driver.intent.json', {'run_id': cfg['run_id'], 'config_sha256': args.config_sha256,
        'started_utc': clock().isoformat(), 'work_deadline_utc': cfg['work_deadline_utc']})
    write_new(out/'b-isolation.json', isolated)
    env = child_environment(cfg, out)
    source_tests(cfg, out, env, test_deadline)

    # Application imports follow actual isolation/source/controller checks/tests.
    sys.path.insert(0, str(Path(cfg['source_directory'])/'src'))
    from cas_forex_revamp.contracts import InferenceBudget, RunScope, canonical_bytes, content_digest
    from cas_forex_revamp.operator.model import ActualModelDecisionAdapter, ModelSpecification
    from cas_forex_revamp.operator.ollama_backend import OllamaRuntimePin
    from cas_forex_revamp.operator.runtime_observer import LinuxRuntimeObserver, PinnedFile, SupervisorSpec, process_stat
    from cas_forex_revamp.composition.isolated_controller import IsolatedController
    from cas_forex_revamp.composition.generation_transport import PendingChangeBridge
    from cas_forex_revamp.operator.token_preflight import tokenizer_identity
    from cas_forex_revamp.composition.evidence_journal import EvidenceJournal
    from cas_forex_revamp.composition.model_evidence_bridge import ModelDecisionReader
    from cas_forex_revamp.composition.r6_budget import ModelWindow, SharedBudgetModelStore
    from cas_forex_revamp.composition.custody_adapter import adapt_custody, FORMATS
    from cas_forex_revamp.composition.custody_schema import load_json
    from cas_forex_revamp.composition.r6_scoring import score_suite
    from cas_forex_revamp.composition.r6_readback import AttemptReader
    from cas_forex_revamp.composition.r6_runtime import packet_json
    from cas_forex_revamp.composition.r6_design import validate_recovered_design
    from cas_forex_revamp.composition.continuous_model_driver_v2 import run_trajectory

    evidence = cfg['evidence']
    # This is the single model clock, before sealed-data validation or startup.
    window = ModelWindow(absolute_deadline=deadline, clock=clock)
    read_fd,write_fd=os.pipe()
    try:
        watchdog = subprocess.Popen(['/usr/bin/python3','-B',str(Path(cfg['source_directory'])/'model_window_watchdog.py'),
            '--parent-pid',str(os.getpid()),'--deadline-utc',window.end.isoformat(),
            '--monotonic-deadline',str(window.tick+(window.end-window.started).total_seconds()),'--ready-fd',str(write_fd)],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,start_new_session=True,pass_fds=(write_fd,))
    finally:os.close(write_fd)
    try:
        ready=select.select([read_fd],[],[],5)[0]
        need(ready and os.read(read_fd,64)==b'R6-WINDOW-READY\n' and watchdog.poll() is None,
             'independent exact-parent deadline watchdog unavailable')
    finally:os.close(read_fd)
    scope = RunScope('synthetic-model-evidence', cfg['run_id'], 1, cfg['build_id'], 'model-budget-1', 'sealed-b', 'independent-simulator-1')
    journal = EvidenceJournal(out/'model-anchor.evidence.sqlite3', scope.key); journal.initialize(create=True)
    store = SharedBudgetModelStore(out/'inference.model-evidence.sqlite3', run_id=cfg['run_id'], deadline=window.end)
    store.bind_window(window); store.bind_journal(journal, scope, clock)
    store.initialize(create=True); store.retain_window(now=clock())
    files = tuple(PinnedFile(**r) for r in cfg['role_files'])
    roles = {f.role: f for f in files}
    pin_source = load((Path(cfg['source_directory'])/'docs/operator/stage-b-runtime-pin.json').read_bytes())
    expected_model = pin_source['model_candidate']
    need(roles['manifest'].sha256 == expected_model['manifest_sha256'] and roles['manifest'].bytes == expected_model['manifest_bytes'], 'manifest differs from reviewed model')
    expected_blobs = {r['digest'][7:]: r['declared_bytes'] for r in expected_model['blobs']}
    need({roles[k].sha256: roles[k].bytes for k in ('weight', 'template', 'parameters', 'config', 'license')} == expected_blobs,
         'reviewed model artifact set differs')
    need(roles['ollama'].path == cfg['ollama_binary'] and roles['runner'].path == cfg['runner_binary'], 'supervised executable roles differ')
    schema_bytes = (Path(cfg['source_directory'])/'docs/contracts/decision-selection.schema.json').read_bytes()
    need(sha256(schema_bytes).hexdigest() == pin_source['wire']['selection_schema_sha256'], 'selection wire schema differs')
    controller = None; report = {'status': 'INCOMPLETE', 'stage_b': 'NOT_RUN', 'u0': 'NOT_RUN', 'u1': 'NOT_RUN', 'error_type': None}
    attempts, trajectories = [], []
    pin = supervisor = None
    try:
        window.require_remaining(5)
        probe_gate = PhaseGate(cfg, 'probe', clock=clock, shared_window=window)
        pending_changes = PendingChangeBridge()
        controller = IsolatedController(cfg=cfg, out=out, window=window, store=store,
            journal=journal, scope=scope, pending_changes=pending_changes, clock=clock)
        controller.start()  # clean roles and externally verified release BEFORE private content
        journal.append('sealed-bundle-exposure', 'SEALED_BUNDLE_EXPOSURE_INTENT', scope,
            {'custody_sha256': {name:evidence[name]['sha256'] for name in FORMATS},
             'consumes_all_members_on_controller_read': True, 'never_reuse_as_unseen': True}, now=clock())
        documents = {}
        for name in FORMATS:
            read_record(evidence[name], base)  # confinement/ownership/raw SHA first
            documents[name] = load_json(Path(evidence[name]['path']).read_bytes())
        keys = documents['keys']
        definitions = read_record(evidence['r6_definition'], base)
        validate_recovered_design(definitions)
        review = read_record(evidence['case_review'], base)
        exposure = read_record(evidence['case_exposure'], base)
        need(documents['suite']['r6_definition_sha256'] == evidence['r6_definition']['sha256'], 'R6 source definition pin differs')
        need(exposure.get('authorized_execution_id') == cfg['run_id']
             and exposure.get('custody_sha256') == {name:evidence[name]['sha256'] for name in FORMATS}
             and exposure.get('prior_model_calls') == 0 and exposure.get('fresh_for_this_one_use_run') is True
             and exposure.get('authorized_implementation_private_reads') == 0,
             'independent one-use custody/exposure record missing')
        suite = adapt_custody(documents, schema_directory=Path(cfg['source_directory'])/'docs/contracts/custody-interface-02',
                             definitions=definitions, reviewed_binding=review)
        planned = suite['planned_calls']
        journal.append('sealed-suite-attempt', 'SEALED_SUITE_ATTEMPT', scope,
            {'suite_sha256': evidence['suite']['sha256'], 'keys_sha256': evidence['keys']['sha256'],
             'planned_calls': planned, 'first_attempt_only': True}, now=clock())
        pin = controller.pin; supervisor = controller.supervisor
        model = pin.model
        readers = controller.readers
        def adapter_for(phase, gate):
            caps = PHASES[phase]
            def guarded(invocation):
                need(watchdog.poll() is None, 'independent model watchdog exited')
                gate(invocation)
            backend, verifier = controller.adapter_backend(phase, guarded)
            adapter = ActualModelDecisionAdapter(adapter_id='ollama-'+phase, model=model,
                budget=InferenceBudget(*caps), backend=backend, receipt_verifier=verifier,
                execution_gate=guarded, clock=clock, session_prefix=cfg['run_id']+'-'+phase,
                seed=cfg['seed'], packet_builder=packet_json)
            adapter.prepare_source_binding = controller.prepare_source_binding
            return adapter
        probe = adapter_for('probe', probe_gate)
        for index in (1, 2):
            request = probe_request(index, cfg['run_id'], clock)
            controller.prepare_source_binding(request, {
                'scope': request.state.scope, 'policy_sha256': content_digest({'probe': True}),
                'policy_revision': 0, 'context_sha256': content_digest({'probe': True}), 'context_version': 0},
                {'probe_state': request.state}, lambda r=request: r.state)
            result = probe.decide(request)
            readers['probe'](load(canonical_bytes(request)), load(canonical_bytes(result)))
            need(result.selection.selected_action_ref is None, 'availability fixture must choose WAIT')
        need(clock() < probe_gate.end and probe.attempted_calls == 2, 'bounded two-call availability probe incomplete')
        write_new(out/'availability-probe.json', {'status': 'PASS', 'actual_calls': probe.attempted_calls,
            'completed_utc': clock().isoformat(), 'model_checkpoint': store.checkpoint(),
            'strategy_or_acceptance_claim': False})
        acceptance_gate = PhaseGate(cfg, 'acceptance', clock=clock, shared_window=window)
        adapter = adapter_for('acceptance', acceptance_gate)
        for case in suite['trajectories']:
            # Failures retain the entire fixed denominator. No substitute cases.
            try:
                window.require_remaining(125)
                journal.append('pair-exposure-'+case['case_id'], 'CASE_PAIR_EXPOSURE_INTENT', scope,
                    {'pair_sha256':suite['pair_consumption_ids'][case['case_id']], 'case_id':case['case_id'],
                     'both_members_consumed':True}, now=clock())
                rows, snapshot = run_trajectory(case, directory=out/('trajectory-'+case['case_id']),
                    execution_id=cfg['run_id'], build_id=cfg['build_id'], adapter=adapter,
                    model_store=store, model_reader=readers['acceptance'], pending_changes=pending_changes, clock=clock)
                attempts.extend(rows); trajectories.append(snapshot)
                journal.append('trajectory-'+case['case_id'], 'R6_TRAJECTORY_CHECKPOINT', scope,
                    {'case_id':case['case_id'], 'scope':snapshot['scope'],
                     'evidence_checkpoint':snapshot['evidence_checkpoint'],
                     'venue_checkpoint':snapshot['venue']['checkpoint'],
                     'core_event_sha256':snapshot['core']['event_sha256']}, now=clock())
            except Exception as exc:
                trajectories.append({'case_id': case['case_id'], 'error_type': type(exc).__name__})
                break
            if any(r.get('error_type') not in (None, 'StaleDecision') for r in rows):
                break
        reader = AttemptReader(root=out.resolve(), controller_journal=journal, model_reader=readers['acceptance'])
        report = score_suite(suite, keys, attempts, verify_attempt=reader)
        need(clock() < acceptance_gate.end and time.monotonic()-acceptance_gate.tick <= 5400,
             'acceptance outcome exceeded its original phase window')
        report.update(stage_b=report['status'], actual_model_checkpoint=store.checkpoint(), anchor_checkpoint=journal.checkpoint())
    except Exception as exc:
        report['status'] = 'INCOMPLETE'
        report['stage_b'] = 'INCOMPLETE'
        report['error_type'] = type(exc).__name__
    finally:
        if controller is not None:
            controller.close()
        # Retain partial attempts and checkpoints on every outcome, including a
        # failed required condition. These files are not replaced by rescoring.
        write_new(out/'b-first-attempts.json', load(canonical_bytes({'attempts': attempts, 'trajectories': trajectories})))
        write_new(out/'b-readback-context.json', load(canonical_bytes({
            'schema':'forex.retained-model-read/2','scope':scope,'model_window':window.record(),
            'pin':pin,'supervisor':supervisor,'model_checkpoint':store.checkpoint(),
            'anchor_checkpoint':journal.checkpoint(),'run_id':cfg['run_id'],
            'source_manifest_sha256':cfg['source_manifest_sha256'],
            'custody_sha256':{name:evidence[name]['sha256'] for name in FORMATS},
            'first_attempts_sha256':file_hash(out/'b-first-attempts.json')})))
        spent = [r for r in store.records() if r['kind']=='MODEL_HTTP_ATTEMPT' and r['payload']['operation']=='generation']
        report.update(total_generation_attempts=len(spent), total_generation_limit=32,
                      probe_attempts=sum(r['payload']['phase']=='probe' for r in spent), model_window=window.record())
        try:
            window.require_remaining(0)
        except Exception:
            report.update(status='INCOMPLETE',stage_b='INCOMPLETE',error_type='OriginalModelWindowExpired')
        report.update(finished_utc=clock().isoformat(), model_artifact_claim='OBSERVED_RECEIPTS_ONLY',
            suite_sha256=evidence['suite']['sha256'], run_id=cfg['run_id'], no_retries=True,
            profit_claim=False, u0='NOT_RUN_SEPARATE_OWNER_STUDY', u1='NOT_RUN_NO_ADDITIONAL_CALL_ALLOCATION')
        write_new(out/'stage-b-result.json', report)
        stop_group(watchdog)
    return 0 if report.get('stage_b') == 'PASS' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        # Raw tracebacks can contain private paths or record values. The
        # retained controller evidence and final redacted export are the only
        # diagnostic routes; a process exit is never an acceptance result.
        raise SystemExit(1)
