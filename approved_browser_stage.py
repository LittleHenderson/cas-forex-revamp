"""Guest-only explicit fixture/CDP orchestration; no imports start a service."""
from __future__ import annotations
import argparse
from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import sys
import time
from approved_test_driver import end_group, node_environment, stage_a_deadline


def observed_isolation(raw, config, *, uid, now):
    if len(raw) > 16384:
        raise RuntimeError('isolation receipt exceeds byte limit')
    isolation = json.loads(raw)
    observed = datetime.fromisoformat(isolation['observed_utc'].replace('Z', '+00:00'))
    t0 = datetime.fromisoformat(config['t0_utc'].replace('Z', '+00:00')).timestamp()
    if (isolation.get('interfaces') != ['lo'] or type(isolation.get('capabilities')) is not int
            or isolation['capabilities'] != 0 or type(isolation.get('uid')) is not int
            or isolation['uid'] != uid or uid <= 0
            or isolation.get('host_paths_inaccessible') is not True
            or isolation.get('deadline_utc') != config['work_deadline_utc']
            or observed.utcoffset().total_seconds() != 0 or not t0 <= observed.timestamp() <= now):
        raise RuntimeError('actual matching sandbox isolation receipt unavailable')
    return sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-config', type=Path, required=True)
    parser.add_argument('--test-deadline', type=float, required=True)
    args = parser.parse_args()
    cfg = json.loads(args.guest_config.read_text(encoding='utf-8'))
    root = Path(__file__).resolve().parent
    out = Path(os.environ['STATE_DIRECTORY'])
    if not cfg.get('browser_config_path') or not cfg.get('browser_driver_path'):
        raise RuntimeError('pinned browser config/driver not supplied')
    allowed = {row['path']: row for row in cfg['files']}
    for field in ('browser_config_path', 'browser_driver_path', 'node_binary'):
        path = Path(cfg[field])
        row = allowed.get(str(path))
        if row is None or path.is_symlink() or path.stat().st_size != row['bytes'] or sha256(path.read_bytes()).hexdigest() != row['sha256']:
            raise RuntimeError('browser input differs from guest allowlist')
    config_path = Path(cfg['browser_config_path'])
    browser_config = json.loads(config_path.read_text(encoding='utf-8'))
    deadline = min(args.test_deadline, stage_a_deadline(cfg))
    browser_deadline = datetime.fromisoformat(browser_config['work_deadline_utc'].replace('Z', '+00:00')).timestamp()
    if browser_deadline > deadline or time.time() >= deadline - 5:
        raise RuntimeError('browser configuration exceeds remaining test/global deadline')
    # Frozen input declares the gate; only this actual sandbox observation can
    # satisfy it. Never prelabel a not-yet-started sandbox as verified.
    if browser_config.get('isolation_receipt_verified') is not False:
        raise RuntimeError('frozen browser config must leave isolation unverified')
    isolation_path = out/'isolation.json'
    isolation_stat = isolation_path.lstat()
    if not stat.S_ISREG(isolation_stat.st_mode) or isolation_stat.st_size > 16384:
        raise RuntimeError('isolation receipt must be a bounded regular file')
    isolation_raw = isolation_path.read_bytes()
    isolation_sha = observed_isolation(isolation_raw, cfg, uid=os.geteuid(), now=time.time())
    children=[]
    source_read, source_write = os.pipe()
    try:
        with (out/'browser-fixture.stdout.txt').open('xb') as so, (out/'browser-fixture.stderr.txt').open('xb') as se:
            fixture = subprocess.Popen([sys.executable, '-B', '-m', 'cas_forex_revamp.composition.browser_fixture_server',
                '--source-root', str(root), '--state-directory', str(out/'browser-fixture'), '--seed-position',
                '--owner-context-fd', str(source_write)], stdout=so, stderr=se,
                stdin=subprocess.DEVNULL, pass_fds=(source_write,), start_new_session=True)
            children.append(fixture)
        os.close(source_write); source_write = -1
        context=b''
        ready_until=min(deadline-5,time.time()+30)
        while True:
            remaining=ready_until-time.time()
            if remaining<=0 or not select.select([source_read],[],[],remaining)[0]:
                raise RuntimeError('fixture private context unavailable')
            chunk=os.read(source_read, min(8193-len(context),4096))
            if not chunk:
                break
            context+=chunk
            if len(context)>8192:
                raise RuntimeError('fixture context exceeds bound')
        parsed=json.loads(context)
        if parsed.get('synthetic_test_context') is not True or parsed.get('run_id') != cfg['run_id']:
            raise RuntimeError('fixture context differs from isolated test run')
        parsed['isolation_receipt_sha256'] = isolation_sha
        context = json.dumps(parsed, separators=(',', ':')).encode('utf-8')
        if len(context) > 8192:
            raise RuntimeError('bound private context exceeds byte limit')
        browser_read, browser_write=os.pipe()
        try:
            with (out/'browser.stdout.txt').open('xb') as so, (out/'browser.stderr.txt').open('xb') as se:
                browser=subprocess.Popen([cfg['node_binary'], cfg['browser_driver_path'], '--config', str(config_path),
                    '--config-sha256', sha256(config_path.read_bytes()).hexdigest(), '--context-fd', str(browser_read)],
                    stdin=subprocess.DEVNULL, stdout=so, stderr=se, pass_fds=(browser_read,), start_new_session=True,
                    env=node_environment(cfg, os.environ))
                children.append(browser)
            os.close(browser_read); browser_read=-1
            with os.fdopen(browser_write,'wb') as pipe:
                browser_write=-1
                pipe.write(context)
                pipe.flush()
            context=b''; parsed=None
            return browser.wait(timeout=max(0.01,deadline-time.time()-5))
        finally:
            for descriptor in (browser_read,browser_write):
                if descriptor>=0:
                    os.close(descriptor)
    finally:
        for descriptor in (source_read,source_write):
            if descriptor>=0:
                os.close(descriptor)
        for child in reversed(children):
            end_group(child)


if __name__=='__main__':
    raise SystemExit(main())
