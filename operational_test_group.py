"""Pinned test subprocess source. Importing runs nothing.

The selected CompletionObserver owns execution approval, actual process/stream
capture and the original outer/test deadline. This command grants no authority.
It runs one complete frozen Python group and emits its actual framework report.
"""
from __future__ import annotations
import argparse
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import unittest

ROOT = Path(__file__).resolve().parent
GROUPS = ('contracts', 'core', 'venue', 'operator', 'rpa', 'integration',
          'provider04', 'policy-inheritance02', 'operational-measurement',
          'operational-authority', 'operational-custody')


def need(value, code):
    if not value:
        raise RuntimeError(code)


def exact_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def pinned_file(path, pin, maximum):
    need(type(pin) is str and len(pin) == 64 and all(c in '0123456789abcdef' for c in pin), 'EXPECTED_PIN')
    need(path.is_absolute() and path.resolve() == path, 'REGULAR_SELECTED_PATH')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum, 'REGULAR_BOUNDED_FILE')
        data = bytearray()
        while len(data) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'FILE_CHANGED')
        need(len(data) == before.st_size and hashlib.sha256(data).hexdigest() == pin, 'FILE_PIN')
        return bytes(data)
    finally:
        os.close(fd)


def utc(value):
    need(type(value) is str and value.endswith('Z'), 'UTC_REQUIRED')
    result = datetime.fromisoformat(value[:-1] + '+00:00')
    need(result.utcoffset() == timedelta(0), 'UTC_REQUIRED')
    return result


def original_test_deadline(record, *, now):
    # Closed source-only successor or unchanged historical shape. No new clock.
    need(type(record) is dict, 'ORIGINAL_CLOCK_FIELDS')
    expected = ({'format', 'bootstrap_started_utc', 'test_deadline_utc'}
        if record.get('format') == 'forex.original-source-test-clock/1' else
        {'model_window', 'model_calls', 'retry_calls', 'bootstrap_started_utc', 'test_deadline_utc'})
    need(set(record) == expected, 'ORIGINAL_CLOCK_FIELDS')
    begin, end = utc(record['bootstrap_started_utc']), utc(record['test_deadline_utc'])
    need(begin <= now < end <= begin + timedelta(seconds=7200), 'ORIGINAL_TEST_WINDOW')
    return end


def identifiers(suite):
    result = []
    for item in suite:
        result.extend(identifiers(item) if isinstance(item, unittest.TestSuite) else [item.id()])
    return result


def require_complete(actual, expected):
    need(type(expected) is list and expected and len(expected) == len(set(expected)), 'EXPECTED_INVENTORY')
    need(len(actual) == len(set(actual)) and sorted(actual) == sorted(expected), 'COMPLETE_TEST_INVENTORY_MISMATCH')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--group', choices=GROUPS, required=True)
    parser.add_argument('--inventory-sha256', required=True)
    parser.add_argument('--original-clock', type=Path, required=True)
    parser.add_argument('--original-clock-sha256', required=True)
    parser.add_argument('--discovery-fd', type=int, required=True)
    parser.add_argument('--release-fd', type=int, required=True)
    args = parser.parse_args()
    need(sys.platform == 'linux' and sys.version_info[:2] == (3, 12) and sys.flags.isolated,
         'SELECTED_LINUX_PYTHON312_ISOLATED_REQUIRED')
    record = exact_json(pinned_file(args.original_clock, args.original_clock_sha256, 16384))
    end = original_test_deadline(record, now=datetime.now(timezone.utc))
    inventory = exact_json(pinned_file(ROOT / 'operational-test-selection.json', args.inventory_sha256, 4_194_304))
    groups = [g for g in inventory['groups'] if g['group_id'] == args.group]
    need(len(groups) == 1 and groups[0]['mode'] == 'PYTHON_METHODS', 'EXACT_GROUP_SELECTION')
    selected = groups[0]
    def stop(signum, frame):
        raise TimeoutError('ORIGINAL_TEST_DEADLINE')
    signal.signal(signal.SIGALRM, stop)
    remaining = (end - datetime.now(timezone.utc)).total_seconds()
    need(remaining > 0, 'ORIGINAL_TEST_WINDOW')
    signal.setitimer(signal.ITIMER_REAL, remaining)
    try:
        for relative in reversed(selected['python_paths']):
            path = ROOT / relative
            need(path.resolve() == path and path.is_dir(), 'FROZEN_IMPORT_PATH')
            sys.path.insert(0, str(path))
        directory, top = ROOT / selected['directory'], ROOT / selected['top_level_directory']
        # Test diagnostics must not masquerade as the canonical stdout report.
        with contextlib.redirect_stdout(sys.stderr):
            suite = unittest.TestLoader().discover(str(directory), pattern='test_*.py', top_level_dir=str(top))
            collected = identifiers(suite)
            require_complete(collected, selected['expected_test_ids'])
            original_test_deadline(record, now=datetime.now(timezone.utc))
            from discovery_channel import exchange
            exchange(discovery_fd=args.discovery_fd, release_fd=args.release_fd,
                group_id=args.group, inventory_sha256=args.inventory_sha256, ids=collected,
                remaining=lambda: (end-datetime.now(timezone.utc)).total_seconds())
            original_test_deadline(record, now=datetime.now(timezone.utc))
            from cas_forex_measurement.completion import python_framework_report
            report = python_framework_report(suite, group_id=args.group)
        original_test_deadline(record, now=datetime.now(timezone.utc))
        require_complete(report['collected_test_ids'], selected['expected_test_ids'])
        require_complete(report['executed_test_ids'], selected['expected_test_ids'])
        sys.stdout.write(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n')
        sys.stdout.flush()
        counts = report['counts']
        return 0 if report['status'] == 'PASS' and not any(counts[k] for k in ('skipped', 'failures', 'errors', 'cancelled', 'todo')) else 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == '__main__':
    raise SystemExit(main())
