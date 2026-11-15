"""Explicit guest-only bounded test/A entrypoint. Importing starts nothing.

Called only by the frozen infrastructure supervisor after actual stop/isolation/
egress proofs. This driver does not provision, install, start a model or claim B.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parent
GROUPS = ('contracts', 'core', 'venue', 'operator', 'rpa', 'integration')
RUN_ROOT = Path('/opt/cas-forex/fx-20261010-8e1a63c5')


def node_environment(config, base):
    """Use only verified private libraries for this Node child."""
    directories = config.get('node_library_directories')
    if not isinstance(directories, list) or not directories:
        raise RuntimeError('pinned private Node library directories required')
    allowed = {row['path'] for row in config['files']}
    result = dict(base)
    result.pop('LD_PRELOAD', None)
    result.pop('LD_LIBRARY_PATH', None)
    result.pop('NODE_OPTIONS', None)
    for value in directories:
        path = Path(value)
        if (not path.is_absolute() or not path.is_relative_to(RUN_ROOT / 'runtime/ubuntu')
                or not path.is_dir() or path.resolve() != path
                or not any(Path(item).parent == path for item in allowed)):
            raise RuntimeError('Node library directory is absent or outside verified runtime')
    result['LD_LIBRARY_PATH'] = ':'.join(directories)
    return result


def stage_a_deadline(config):
    def utc(field):
        value = datetime.fromisoformat(config[field].replace('Z', '+00:00'))
        if value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
            raise RuntimeError('UTC execution timestamps required')
        return value.timestamp()
    t0, global_end = utc('t0_utc'), utc('work_deadline_utc')
    bootstrap, stage_end = utc('bootstrap_started_utc'), utc('stage_a_deadline_utc')
    if (global_end - t0 != 13200 or not t0 <= bootstrap < stage_end
            or stage_end > min(global_end, bootstrap + 7200)):
        raise RuntimeError('bootstrap and tests must share the original 120-minute budget')
    return stage_end


def end_group(child):
    # A main process can exit while descendants still hold files or sockets.
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        child.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait(timeout=1)


def write_new(path, payload):
    with path.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
        handle.flush()
        os.fsync(handle.fileno())


def test_group(name, output):
    if name not in GROUPS:
        raise RuntimeError('unknown test group')
    directory = ROOT / 'tests' / name
    sys.path.insert(0, str(ROOT / 'src'))
    sys.path.insert(0, str(directory))
    # Venue uses package-relative support; operator tests intentionally use its
    # sibling test_operator module. Fresh processes keep these imports separate.
    top = ROOT / 'tests' if name == 'venue' else directory
    suite = unittest.TestLoader().discover(str(directory), pattern='test_*.py', top_level_dir=str(top))
    count = suite.countTestCases()
    if count <= 0:
        raise RuntimeError('empty test group cannot pass')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = dict(group=name, discovered=count, ran=result.testsRun, failures=len(result.failures),
                  errors=len(result.errors), skipped=len(result.skipped),
                  status='PASS' if result.wasSuccessful() and not result.skipped and result.testsRun == count else 'FAIL')
    write_new(output, report)
    return 0 if report['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-config', type=Path)
    parser.add_argument('--test-group', choices=GROUPS)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.test_group:
        if args.output is None:
            raise RuntimeError('explicit retained output required')
        return test_group(args.test_group, args.output)
    if args.guest_config is None or platform.system() != 'Linux' or sys.version_info[:2] != (3, 12):
        raise RuntimeError('approved Linux Python 3.12 guest/config required')
    config = json.loads(args.guest_config.read_text(encoding='utf-8'))
    if (config.get('execution_mode') != 'STAGE_A_ONLY'
            or config.get('model_launch_allowed') is not False
            or type(config.get('model_inference_calls_limit')) is not int
            or config['model_inference_calls_limit'] != 0
            or config.get('stage_b_status') != 'BLOCKED'):
        raise RuntimeError('explicit Stage A-only configuration with zero model authority required')
    if config.get('independent_stop_proof_verified') is not True or config.get('bootstrap_egress_revoke_verified') is not True:
        raise RuntimeError('actual independent stop and sealed-egress receipts required')
    deadline = stage_a_deadline(config)
    out = Path(os.environ['STATE_DIRECTORY']).resolve()
    isolation = json.loads((out / 'isolation.json').read_text(encoding='utf-8'))
    if (isolation.get('interfaces') != ['lo'] or isolation.get('capabilities') != 0
            or isolation.get('deadline_utc') != config['work_deadline_utc']):
        raise RuntimeError('matching observed guest isolation is required')
    node = Path(config['node_binary'])
    allowed = {row['path'] for row in config['files']}
    if str(node) not in allowed or str(Path(__file__).resolve()) not in allowed:
        raise RuntimeError('driver/Node missing from frozen guest allowlist')
    with (out / 'test-stage.intent.json').open('x', encoding='utf-8') as stream:
        json.dump(dict(started_at=datetime.now(timezone.utc).isoformat(), work_deadline_utc=config['work_deadline_utc'],
                       bootstrap_started_utc=config['bootstrap_started_utc'], stage_a_deadline_utc=config['stage_a_deadline_utc']), stream)
        stream.flush()
        os.fsync(stream.fileno())
    started = time.monotonic()
    env = dict(os.environ)
    for inherited in ('LD_LIBRARY_PATH', 'LD_PRELOAD', 'NODE_OPTIONS'):
        env.pop(inherited, None)
    env['PYTHONPATH'] = str(ROOT / 'src')
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    # All test-created stores live in retained StateDirectory, not source or model roots.
    temporary = out / 'test-temporary'
    temporary.mkdir(exist_ok=False)
    env['TMPDIR'] = str(temporary)
    results = []
    browser_status = 'NOT_RUN'
    def run(name, argv, *, child_env=None):
        remaining = min(deadline - time.time() - 5, 7200 - (time.monotonic() - started))
        if remaining <= 0:
            raise RuntimeError('test/A stage or global deadline exhausted')
        with (out / (name + '.stdout.txt')).open('xb') as stdout, (out / (name + '.stderr.txt')).open('xb') as stderr:
            child = subprocess.Popen(argv, cwd=ROOT, env=child_env or env, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                returncode = child.wait(timeout=remaining)
            finally:
                end_group(child)
        results.append(dict(stage=name, exit_code=returncode))
        if returncode:
            raise RuntimeError(name + ' failed; later stages blocked')
    try:
        node_env = node_environment(config, env)
        run('node-version', [str(node), '--version'], child_env=node_env)
        if (out / 'node-version.stdout.txt').read_text(encoding='utf-8').strip() != 'v24.21.0':
            raise RuntimeError('observed Node version differs from frozen release')
        for group in GROUPS:
            run('python-' + group, [sys.executable, '-B', str(Path(__file__).resolve()), '--test-group', group,
                                   '--output', str(out / ('python-' + group + '.json'))])
        ui_tests = sorted(ROOT.glob('tests/ui/*.test.mjs'))
        if not ui_tests:
            raise RuntimeError('empty UI test group')
        run('node-ui', [str(node), '--test', '--test-reporter=tap', *map(str, ui_tests)], child_env=node_env)
        run('continuous-a', [sys.executable, '-B', '-m', 'cas_forex_revamp.composition.continuous_driver',
                             'run', str(out / 'continuous-a')])
        result = json.loads((out / 'continuous-a/continuous-a-result.json').read_text(encoding='utf-8'))
        if result.get('status') != 'PASS' or len(result.get('checks', [])) != 16:
            raise RuntimeError('continuous A did not provide all checkpoints')
        browser_status = 'BLOCKED'
        if config.get('browser_config_path') and config.get('browser_driver_path'):
            test_deadline = min(deadline, time.time() + 7200 - (time.monotonic() - started))
            browser_status = 'STARTED'
            run('browser-g4', [sys.executable, '-B', str(ROOT/'approved_browser_stage.py'),
                               '--guest-config', str(args.guest_config), '--test-deadline', str(test_deadline)])
            browser_status = 'PASS'
        write_new(out / 'test-stage-result.json', dict(status='PASS', stages=results, continuous_a='PASS',
                  browser=browser_status, actual_model_b='BLOCKED', inference_calls=0,
                  reason='Actual-model gates require the separately pinned integrated driver; test-stage PASS does not mean whole-project acceptance.',
                  finished_at=datetime.now(timezone.utc).isoformat()))
    except BaseException as error:
        write_new(out / 'test-stage-result.json', dict(status='FAIL', stages=results,
                  error_type=type(error).__name__,
                  browser='FAILED_OR_INTERRUPTED' if browser_status == 'STARTED' else browser_status,
                  actual_model_b='NOT_RUN', inference_calls=0))
        raise
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
